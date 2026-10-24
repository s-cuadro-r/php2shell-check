/** Browser-only, passive assessment of public HTTP headers observed through HackerTarget. */
export const FIXED_PATCHES = Object.freeze({'8.2':35,'8.3':36,'8.4':27,'8.5':12});
/** Ramas con soporte de seguridad activo según php.net, ordenadas. Fuera de este rango, la rama es EOL (más baja) o aún no cubierta por el aviso (más alta). */
const KNOWN_BRANCHES = Object.keys(FIXED_PATCHES).map(b => b.split('.').map(Number)).sort((a,b) => a[0]-b[0] || a[1]-b[1]);
const MIN_KNOWN_BRANCH = KNOWN_BRANCHES[0];
/**
 * Mitigación parcial (no reemplaza el parche). Fuentes: PHP core dev Gina Peter Banyard
 * ("the only mitigation is patching / upgrading PHP"); GMO Flatt Security revisó su postura
 * inicial a "may help, but the attack is still possible". session.upload_progress.enabled=0
 * cubre solo CVE-2026-109619 (no CVE-2026-109618, una ruta de agotamiento de memoria separada).
 */
const MITIGATION_PARTIAL = 'Mitigación parcial mientras actualizás (no reemplaza el parche, cubre solo algunos caminos de ataque, no deja el sitio seguro por sí sola): session.upload_progress.enabled=0 en php.ini o el pool de FPM —reiniciando los workers; no alcanza con ini_set() ni .user.ini— cubre únicamente CVE-2026-109619. Un memory_limit fijo no modificable por la aplicación y un post_max_size bajo ayudan contra CVE-2026-109618, la otra CVE. Según el propio equipo de PHP, la única mitigación real es aplicar el parche.';
const RESERVED_ENDINGS = /\.(?:localhost|local|internal|intranet|lan|home|arpa|invalid|test|onion)$/i;
const REDIRECTS = new Set([301,302,303,307,308]);
const MAX_BYTES = 65536;
/** Cabeceras públicas que delatan de forma fiable un WAF/CDN conocido delante del origen. */
const EDGE_HEADER_PROVIDERS = Object.freeze({'cf-ray':'Cloudflare','cf-cache-status':'Cloudflare','x-sucuri-id':'Sucuri','x-sucuri-cache':'Sucuri','x-iinfo':'Imperva/Incapsula','x-amz-cf-id':'Amazon CloudFront','x-akamai-transformed':'Akamai','x-azure-ref':'Azure Front Door'});
const SERVER_EDGE_SIGNATURES = Object.freeze([[/cloudflare/i,'Cloudflare'],[/akamaighost/i,'Akamai'],[/sucuri/i,'Sucuri'],[/imperva|incapsula/i,'Imperva/Incapsula'],[/cloudfront/i,'Amazon CloudFront'],[/\bfastly\b/i,'Fastly']]);
/** Cabeceras puramente informativas (plataforma/panel de hosting) que algunos proveedores agregan; no afectan el veredicto. */
const INFO_HEADERS = ['server','platform','panel'];
const CAPTURED_HEADERS = new Set(['server','x-powered-by','location',...INFO_HEADERS,...Object.keys(EDGE_HEADER_PROVIDERS)]);
/**
 * URL de un endpoint propio de consulta pasiva de cabeceras (por ejemplo, el Worker
 * de Cloudflare en worker/header-check.js, desplegado bajo tu propia cuenta gratuita).
 * Vacío: se usa la API pública de HackerTarget, que comparte una cuota chica por IP
 * entre todos los visitantes de esta página y puede devolver "cuota excedida" con
 * poco uso. Con tu propio endpoint desplegado, cada visitante usa tu cuota propia
 * (100.000 requests/día en la capa gratuita de Workers), sin ese límite compartido.
 * Pegá acá la URL que te da `wrangler deploy` (ver instrucciones en worker/header-check.js).
 */
export const SELF_HOSTED_ENDPOINT = 'https://php2shell-headers.s-cuadro-r.workers.dev';
export class InputError extends Error {}
export class ProviderError extends Error {}

export function normalizeDomain(value) {
  if (typeof value !== 'string') throw new InputError('Ingresá un dominio válido.');
  const input = value.trim();
  if (!input || input.length > 300 || /[\s\\\u0000-\u001f\u007f]/u.test(input)) throw new InputError('Ingresá solo el dominio, por ejemplo sitio.edu.uy.');
  const explicitScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(input);
  let url;
  try { url = new URL(explicitScheme ? input : 'https://' + input); } catch { throw new InputError('El dominio no tiene un formato válido.'); }
  if (url.protocol !== 'https:') throw new InputError('Usá un dominio o una dirección HTTPS.');
  const authority = (explicitScheme ? input.replace(/^[a-z][a-z0-9+.-]*:\/\//i,'') : input).split(/[/?#]/,1)[0];
  if (url.username || url.password || authority.includes('@') || authority.includes(':')) throw new InputError('Ingresá un dominio sin usuario, contraseña ni puerto.');
  if (url.pathname !== '/' || url.search || url.hash || input.includes('?') || input.includes('#')) throw new InputError('Ingresá solo el dominio, sin rutas, parámetros ni fragmentos.');
  const domain = url.hostname.toLowerCase().replace(/\.$/,'');
  const labels = domain.split('.');
  if (domain.length > 253 || labels.length < 2 || RESERVED_ENDINGS.test(domain) || labels.some(label => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(label)) || !/^(?:[a-z]{2,63}|xn--[a-z0-9-]{2,59})$/i.test(labels.at(-1) || '') || /^(?:\d{1,3}\.){3}\d{1,3}$/.test(domain)) throw new InputError('Se requiere un nombre de dominio público válido.');
  return domain;
}

export function isPublicAddress(address) {
  if (typeof address !== 'string') return false;
  const parts = address.split('.');
  if (parts.length === 4 && parts.every(part => /^(?:0|[1-9]\d{0,2})$/.test(part) && Number(part) <= 255)) {
    const [a,b,c] = parts.map(Number);
    return !(a === 0 || a === 10 || a === 127 || a >= 224 || (a === 100 && b >= 64 && b <= 127) || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && (b === 168 || (b === 0 && (c === 0 || c === 2)) || (b === 88 && c === 99))) || (a === 198 && (b === 18 || b === 19 || (b === 51 && c === 100))) || (a === 203 && b === 0 && c === 113));
  }
  if (!/^[0-9a-f:]+$/i.test(address) || address.includes(':::')) return false;
  const halves = address.split('::');
  if (halves.length > 2) return false;
  const parse = half => !half ? [] : half.split(':').every(item => /^[0-9a-f]{1,4}$/i.test(item)) ? half.split(':').map(item => parseInt(item,16)) : null;
  const left = parse(halves[0]);
  const right = parse(halves[1] || '');
  if (!left || !right) return false;
  const zeros = 8 - left.length - right.length;
  const ip = halves.length === 1 ? (left.length === 8 ? left : null) : zeros > 0 ? [...left,...Array(zeros).fill(0),...right] : null;
  return !!ip && (ip[0] & 0xe000) === 0x2000 && !(ip[0] === 0x2001 && (ip[1] <= 0x01ff || ip[1] === 0x0db8)) && ip[0] !== 0x2002 && !(ip[0] === 0x3fff && (ip[1] & 0xf000) === 0);
}

function versionsFrom(block) {
  const versions = new Set();
  let nonStable = false;
  for (const name of ['x-powered-by','server']) {
    for (const value of block.headers[name] || []) {
      if (!/\bPHP(?:\s*\/|\b)/i.test(value)) continue;
      const tokens = [...value.matchAll(/\bPHP\s*\/\s*([^\s;,()]+)/gi)];
      if (!tokens.length) nonStable = true;
      const remainder = value.replace(/\bPHP\s*\/\s*[^\s;,()]+/gi,'');
      if (/\bPHP\b/i.test(remainder)) nonStable = true;
      for (const [,token] of tokens) {
        const stable = /^(\d{1,2}\.\d{1,3}\.\d{1,5})([^\s]*)$/.exec(token);
        if (!stable || (stable[2] && !/^[-+][a-z0-9][a-z0-9.+~_-]*$/i.test(stable[2])) || /(?:dev|alpha|beta|rc|snapshot|preview|pre)/i.test(stable[2])) nonStable = true;
        else versions.add(stable[1]);
      }
    }
  }
  return {versions:[...versions].sort(),nonStable};
}

export function parseHeaderBlocks(raw) {
  if (typeof raw !== 'string' || raw.length > MAX_BYTES || /\u0000/.test(raw)) throw new ProviderError('El proveedor devolvió una respuesta de cabeceras no válida.');
  if (/api\s+(?:count|quota|limit)|rate.?limit|quota.*exceed|too many requests|exceeded.*limit/i.test(raw)) throw new ProviderError('HackerTarget alcanzó su cuota de consultas. Esperá y volvé a intentar más tarde.');
  const blocks = [];
  let current = null;
  for (const line of raw.replace(/\r\n/g,'\n').split('\n')) {
    const match = /^HTTP\/(?:1\.[01]|2(?:\.0)?|3(?:\.0)?)\s+([1-5]\d\d)(?:[ \t]+(.*))?$/i.exec(line.trim());
    if (match) {
      current = {status:Number(match[1]),headers:{},malformed:false,proxyHandshake:/^connection established\s*$/i.test(match[2] || '')};
      blocks.push(current);
      if (blocks.length > 12) throw new ProviderError('La respuesta contiene demasiadas redirecciones o bloques de cabeceras.');
      continue;
    }
    if (!line.trim()) continue;
    if (!current) throw new ProviderError('No se obtuvieron cabeceras HTTP válidas. El sitio puede estar inaccesible o el proveedor puede haber rechazado la consulta.');
    const field = /^([!#$%&'*+.^_`|~0-9a-z-]+):[ \t]*(.*)$/i.exec(line);
    if (!field || line.length > 8192) { current.malformed = true; continue; }
    const name = field[1].toLowerCase();
    if (CAPTURED_HEADERS.has(name)) {
      current.headers[name] ||= [];
      current.headers[name].push(field[2].slice(0,4096));
      if (current.headers[name].length > 12) current.malformed = true;
    }
  }
  const useful = [];
  for (const block of blocks) {
    if (block.status < 200 || block.proxyHandshake) {
      if (useful.length) throw new ProviderError('La cadena HTTP termina o continúa con un bloque incompleto; no se puede evaluar una versión.');
    } else useful.push(block);
  }
  if (!useful.length) throw new ProviderError('El proveedor no devolvió una respuesta HTTP final que se pueda evaluar.');
  return useful;
}

/** Proveedores de WAF/CDN conocidos cuyas cabeceras públicas aparecen en algún bloque de la cadena. */
function edgeProvidersFrom(blocks) {
  const providers = new Set();
  for (const block of blocks) {
    for (const [name,label] of Object.entries(EDGE_HEADER_PROVIDERS)) if ((block.headers[name] || []).length) providers.add(label);
    for (const value of block.headers.server || []) for (const [regex,label] of SERVER_EDGE_SIGNATURES) if (regex.test(value)) providers.add(label);
  }
  return [...providers].sort();
}

function edgeCaveat(edgeProviders) {
  return edgeProviders.length ? ` El camino de red observado muestra señales de ${edgeProviders.join(', ')}; la respuesta pública puede reflejar ese borde y no el servidor de origen. Confirmá la versión real desde el propio servidor cuando haya un WAF o CDN delante.` : '';
}

function unknown(domain,summary,evidence=[],httpStatus=null,phpVersion=null,edgeProviders=[]) {
  return {status:'indeterminate',domain,checkedAt:new Date().toISOString(),verdict:'No se pudo determinar',summary,evidence,phpVersion,httpStatus,url:'https://' + domain + '/',recommendation:'Confirmá con la administración del servidor qué paquete de PHP atiende este dominio y si incorpora las correcciones de ambas CVE. La ausencia de una versión pública no demuestra protección.' + edgeCaveat(edgeProviders)};
}

/** The provider already follows redirects. We assess their scope; we cannot stop them retroactively. */
export function assessHeaders(domainInput, raw, initialEvidence=[], providerLabel='HackerTarget') {
  const domain = normalizeDomain(domainInput);
  const blocks = parseHeaderBlocks(raw);
  const final = blocks.at(-1);
  const edgeProviders = edgeProvidersFrom(blocks);
  const evidence = [...initialEvidence,`Cabeceras públicas observadas a través de ${providerLabel}.`,`La respuesta final informada por el proveedor fue HTTP ${final.status}.`];
  if (edgeProviders.length) evidence.push(`Se observaron cabeceras asociadas a ${edgeProviders.join(', ')} en el camino de red; la respuesta pública puede corresponder a ese borde y no al servidor de origen.`);
  const infoParts = INFO_HEADERS.flatMap(name => (final.headers[name] || []).slice(0,1).map(value => `${name}: ${value}`));
  if (infoParts.length) evidence.push(`Información adicional declarada por el sitio (no forma parte del veredicto): ${infoParts.join(', ')}.`);
  let current = new URL('https://' + domain + '/');
  for (let i=0;i<blocks.length;i++) {
    const block = blocks[i];
    if (block.malformed) return unknown(domain,'El proveedor devolvió cabeceras incompletas o ambiguas; no se puede evaluar una versión con certeza.',evidence,final.status,null,edgeProviders);
    if (REDIRECTS.has(block.status)) {
      const locations = block.headers.location || [];
      if (locations.length !== 1 || i === blocks.length-1) return unknown(domain,'La cadena de redirecciones informada no permite establecer una respuesta final dentro del dominio consultado.',evidence,final.status,null,edgeProviders);
      let next;
      try { next = new URL(locations[0],current); } catch { return unknown(domain,'No se pudo interpretar una redirección informada por el proveedor.',evidence,final.status,null,edgeProviders); }
      if (next.protocol !== 'https:' || next.hostname.toLowerCase().replace(/\.$/,'') !== domain || next.username || next.password || next.port) return unknown(domain,'El proveedor informó una redirección fuera del dominio HTTPS consultado. Sus resultados no permiten concluir el estado de este dominio.',evidence,final.status,null,edgeProviders);
      current = next;
    } else if (i !== blocks.length-1) return unknown(domain,'El proveedor devolvió varias respuestas finales y no permite atribuir una versión única al dominio.',evidence,final.status,null,edgeProviders);
  }
  if (final.status < 200 || final.status >= 300) return unknown(domain,'La respuesta final informada no fue exitosa. Puede corresponder a un bloqueo, un error o un sitio que no responde normalmente.',evidence,final.status,null,edgeProviders);
  if (blocks.length > 1) evidence.push(`El proveedor informó ${blocks.length-1} redirecciones HTTPS dentro del mismo dominio.`);
  const observations = blocks.map(versionsFrom);
  const allVersions = [...new Set(observations.flatMap(item => item.versions))];
  const observed = observations.at(-1);
  if (allVersions.length > 1 || observations.some(item => item.nonStable)) return unknown(domain,'Las cabeceras informadas contienen versiones contradictorias, incompletas o preliminares de PHP.',evidence,final.status,null,edgeProviders);
  if (observed.versions.length !== 1) return unknown(domain,'La respuesta final no declara una versión exacta de PHP. El sitio puede ocultarla o utilizar otra tecnología.',evidence,final.status,null,edgeProviders);
  const version = observed.versions[0];
  evidence.push(`La respuesta final declara PHP ${version} en Server o X-Powered-By.`);
  const [major,minor,patch] = version.split('.').map(Number);
  const branch = `${major}.${minor}`;
  const fixedPatch = FIXED_PATCHES[branch];
  if (fixedPatch === undefined) {
    const isEolBranch = major < MIN_KNOWN_BRANCH[0] || (major === MIN_KNOWN_BRANCH[0] && minor < MIN_KNOWN_BRANCH[1]);
    if (isEolBranch) {
      evidence.push(`La rama PHP ${branch} ya no tiene soporte de seguridad activo (fin de vida confirmado en php.net); no existe para ella una versión numerada que incorpore el parche del 21 de octubre de 2026. PHP publicó parches fuente no oficiales para 7.4/8.0/8.1 (para compilaciones propias) y existen backports de distribuciones (Ubuntu, CloudLinux, TuxCare, sury.org) que pueden mantener el mismo número de versión visible: confirmá el changelog real del paquete instalado para ambas CVE antes de descartar este resultado.`);
      return {status:'potentially_affected',domain,checkedAt:new Date().toISOString(),verdict:'Versión potencialmente afectada',summary:`El sitio declara PHP ${version}, de una rama sin soporte de seguridad activo. Sin una versión numerada corregida publicada por PHP.net para esta rama, se trata como potencialmente afectado salvo que el paquete real instalado incluya un backport confirmado de ambas CVE.`,evidence,phpVersion:version,httpStatus:final.status,url:current.href,recommendation:`Solución: migrá a una rama con soporte activo (PHP 8.2.35, 8.3.36, 8.4.27 u 8.5.12, o posterior) — es la corrección completa, ya que esta rama no la recibirá. ${MITIGATION_PARTIAL}` + edgeCaveat(edgeProviders)};
    }
    return unknown(domain,'La rama de PHP declarada es más nueva que las cubiertas por el aviso de seguridad disponible; no hay un umbral de corrección verificado en esta herramienta para ella.',evidence,final.status,version,edgeProviders);
  }
  evidence.push(`Primera versión upstream corregida de esta rama: PHP ${branch}.${fixedPatch}.`);
  const affected = patch < fixedPatch;
  const baseRecommendation = affected?`Solución: actualizá a PHP ${branch}.${fixedPatch} o posterior (o confirmá con tu proveedor que el paquete instalado ya incluye el parche del 21 de octubre de 2026 para ambas CVE). Revisá todos los nodos y reiniciá los procesos PHP después de actualizar. ${MITIGATION_PARTIAL}`:'Confirmá desde el servidor la versión o el parche del paquete y que todos los procesos PHP estén actualizados. Este resultado se limita a CVE-2026-109618 y CVE-2026-109619.';
  return {status:affected?'potentially_affected':'patched_declared',domain,checkedAt:new Date().toISOString(),verdict:affected?'Versión potencialmente afectada':'Versión corregida declarada',summary:affected?`El sitio declara PHP ${version}, anterior a la corrección de su rama. Algunos proveedores aplican parches sin cambiar la versión base; es necesario revisar el paquete instalado.`:`El sitio declara PHP ${version}, igual o posterior a la corrección de su rama. Las cabeceras informadas por un tercero no confirman qué binario se ejecuta ni certifican la seguridad del sitio.`,evidence,phpVersion:version,httpStatus:final.status,url:current.href,recommendation:baseRecommendation + edgeCaveat(edgeProviders)};
}

async function boundedText(response,signal,maxBytes=MAX_BYTES) {
  if (Number(response.headers.get('content-length')) > maxBytes) throw new ProviderError('El proveedor devolvió una respuesta demasiado grande.');
  if (!response.body) return '';
  const reader = response.body.getReader();
  const decoder = new TextDecoder('utf-8',{fatal:true});
  let text = '', size = 0;
  try {
    for (;;) {
      if (signal.aborted) throw new DOMException('Consulta cancelada','AbortError');
      const {done,value} = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > maxBytes) throw new ProviderError('El proveedor devolvió una respuesta demasiado grande.');
      text += decoder.decode(value,{stream:true});
    }
    return text + decoder.decode();
  } finally { await reader.cancel().catch(() => {}); }
}

export async function checkDomain(value,{fetcher=fetch,signal}={}) {
  const domain = normalizeDomain(value);
  const ownController = signal ? null : new AbortController();
  const activeSignal = signal || ownController.signal;
  const timer = ownController ? setTimeout(() => ownController.abort(),15000) : null;
  try {
    const records = await Promise.all(['A','AAAA'].map(async type => {
      const response = await fetcher(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=${type}`,{headers:{Accept:'application/dns-json'},signal:activeSignal,credentials:'omit',cache:'no-store',referrerPolicy:'no-referrer',redirect:'error'});
      if (!response.ok) throw new ProviderError('No se pudo consultar el DNS público. Volvé a intentar.');
      let data;
      try { data = JSON.parse(await boundedText(response,activeSignal,32768)); } catch (err) { if (err?.name === 'AbortError') throw err; throw new ProviderError('No se pudo interpretar la respuesta del DNS público.'); }
      if (data.Status === 3) return [];
      if (data.Status !== 0 || (data.Answer !== undefined && !Array.isArray(data.Answer))) throw new ProviderError('El DNS público no pudo resolver este dominio.');
      return (data.Answer || []).filter(item => item.type === 1 || item.type === 28).map(item => item.data);
    }));
    const addresses = records.flat();
    if (!addresses.length) return unknown(domain,'No se encontraron direcciones públicas para este dominio.');
    if (addresses.length > 64 || addresses.some(address => !isPublicAddress(address))) throw new InputError('El dominio devuelve direcciones no públicas. Esta herramienta solo consulta sitios públicos.');
    const selfHosted = SELF_HOSTED_ENDPOINT.trim();
    const providerLabel = selfHosted ? 'tu endpoint propio' : 'HackerTarget';
    const queryUrl = selfHosted ? selfHosted.replace(/\/$/,'') + '?domain=' + encodeURIComponent(domain) : 'https://api.hackertarget.com/httpheaders/?q=' + encodeURIComponent('https://' + domain + '/');
    const response = await fetcher(queryUrl,{method:'GET',signal:activeSignal,credentials:'omit',cache:'no-store',referrerPolicy:'no-referrer',redirect:'error'});
    if (!response.ok) {
      if (selfHosted) throw new ProviderError(response.status === 429?'Tu endpoint propio alcanzó su propio límite de consultas. Esperá y volvé a intentar más tarde.':'Tu endpoint propio no pudo completar la consulta. Volvé a intentar más tarde.');
      throw new ProviderError(response.status === 429?'HackerTarget alcanzó su cuota de consultas. Esperá y volvé a intentar más tarde.':'HackerTarget no pudo completar la consulta. Volvé a intentar más tarde.');
    }
    const text = await boundedText(response,activeSignal);
    return assessHeaders(domain,text,['El DNS de Cloudflare consultado devolvió únicamente direcciones públicas.'],providerLabel);
  } finally { if (timer) clearTimeout(timer); }
}
