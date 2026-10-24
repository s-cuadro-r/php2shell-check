/**
 * Cloudflare Worker — reemplazo autohospedado de la consulta pasiva de cabeceras
 * que hoy hace checker.js contra la API gratuita de HackerTarget.
 *
 * Por qué existe: HackerTarget impone una cuota muy chica y compartida por IP.
 * Este Worker hace exactamente la misma consulta pasiva (GET a la raíz del
 * dominio, lectura de cabeceras públicas, nada de exploits), pero corriendo
 * bajo tu propia cuenta de Cloudflare. La capa gratuita de Workers permite
 * 100.000 requests/día sin compartir cuota con nadie más.
 *
 * Devuelve el mismo formato de texto que ya entiende parseHeaderBlocks() en
 * checker.js (bloques "HTTP/1.1 <status> ...\r\nHeader: valor\r\n...\r\n\r\n"
 * concatenados por cada salto de redirección), así que no hace falta tocar
 * la lógica de evaluación existente — solo apuntar checker.js a esta URL.
 *
 * Despliegue (una vez, gratis, con tu cuenta de Cloudflare):
 *   npm install -g wrangler
 *   wrangler login
 *   wrangler deploy worker/header-check.js --name php2shell-headers --compatibility-date 2026-10-24
 * Wrangler te da una URL tipo https://php2shell-headers.<tu-cuenta>.workers.dev
 * Esa URL es la que vas a pegar en checker.js (ver SELF_HOSTED_ENDPOINT).
 */

const RESERVED_ENDINGS = /\.(?:localhost|local|internal|intranet|lan|home|arpa|invalid|test|onion)$/i;
const REDIRECTS = new Set([301, 302, 303, 307, 308]);
const CAPTURED_HEADERS = ['server', 'x-powered-by', 'location', 'cf-ray', 'cf-cache-status', 'x-sucuri-id', 'x-sucuri-cache', 'x-iinfo', 'x-amz-cf-id', 'x-akamai-transformed', 'x-azure-ref'];
const MAX_HOPS = 10;
const FETCH_TIMEOUT_MS = 10000;

function validateDomain(raw) {
  if (typeof raw !== 'string') return null;
  const domain = raw.trim().toLowerCase().replace(/\.$/, '');
  if (!domain || domain.length > 253) return null;
  const labels = domain.split('.');
  if (labels.length < 2) return null;
  if (RESERVED_ENDINGS.test(domain)) return null;
  if (labels.some(label => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(label))) return null;
  if (!/^(?:[a-z]{2,63}|xn--[a-z0-9-]{2,59})$/i.test(labels.at(-1) || '')) return null;
  if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(domain)) return null;
  return domain;
}

function isPublicIPv4(address) {
  const parts = address.split('.');
  if (parts.length !== 4 || !parts.every(part => /^(?:0|[1-9]\d{0,2})$/.test(part) && Number(part) <= 255)) return false;
  const [a, b, c] = parts.map(Number);
  return !(a === 0 || a === 10 || a === 127 || a >= 224 || (a === 100 && b >= 64 && b <= 127) || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && (b === 168 || (b === 0 && (c === 0 || c === 2)) || (b === 88 && c === 99))) || (a === 198 && (b === 18 || b === 19 || (b === 51 && c === 100))) || (a === 203 && b === 0 && c === 113));
}

function isPublicIPv6(address) {
  if (!/^[0-9a-f:]+$/i.test(address) || address.includes(':::')) return false;
  const halves = address.split('::');
  if (halves.length > 2) return false;
  const parse = half => !half ? [] : half.split(':').every(item => /^[0-9a-f]{1,4}$/i.test(item)) ? half.split(':').map(item => parseInt(item, 16)) : null;
  const left = parse(halves[0]);
  const right = parse(halves[1] || '');
  if (!left || !right) return false;
  const zeros = 8 - left.length - right.length;
  const ip = halves.length === 1 ? (left.length === 8 ? left : null) : zeros > 0 ? [...left, ...Array(zeros).fill(0), ...right] : null;
  return !!ip && (ip[0] & 0xe000) === 0x2000 && !(ip[0] === 0x2001 && (ip[1] <= 0x01ff || ip[1] === 0x0db8)) && ip[0] !== 0x2002 && !(ip[0] === 0x3fff && (ip[1] & 0xf000) === 0);
}

async function resolvesToPublicAddressOnly(domain) {
  const lookups = await Promise.all(['A', 'AAAA'].map(async type => {
    const res = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=${type}`, { headers: { Accept: 'application/dns-json' } });
    if (!res.ok) return null;
    const data = await res.json().catch(() => null);
    if (!data || data.Status === 3) return [];
    if (data.Status !== 0 || (data.Answer !== undefined && !Array.isArray(data.Answer))) return null;
    return (data.Answer || []).filter(item => item.type === 1 || item.type === 28).map(item => item.data);
  }));
  if (lookups.includes(null)) return false;
  const addresses = lookups.flat();
  if (!addresses.length || addresses.length > 64) return false;
  return addresses.every(address => isPublicIPv4(address) || isPublicIPv6(address));
}

function formatBlock(status, statusText, headers) {
  const lines = [`HTTP/1.1 ${status} ${statusText || ''}`.trimEnd()];
  for (const name of CAPTURED_HEADERS) {
    const value = headers.get(name);
    if (value) lines.push(`${name}: ${value}`);
  }
  return lines.join('\r\n') + '\r\n';
}

async function withTimeout(promise, ms) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), ms);
  try { return await promise(controller.signal); } finally { clearTimeout(timer); }
}

export default {
  async fetch(request) {
    const cors = { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Methods': 'GET, OPTIONS' };
    if (request.method === 'OPTIONS') return new Response(null, { headers: cors });
    if (request.method !== 'GET') return new Response('Method not allowed', { status: 405, headers: cors });

    const url = new URL(request.url);
    const domain = validateDomain(url.searchParams.get('domain') || '');
    if (!domain) return new Response('Dominio inválido.', { status: 400, headers: cors });
    if (!(await resolvesToPublicAddressOnly(domain))) return new Response('El dominio no resuelve a una dirección pública.', { status: 400, headers: cors });

    const blocks = [];
    let current = 'https://' + domain + '/';
    try {
      for (let hop = 0; hop < MAX_HOPS; hop++) {
        const currentUrl = new URL(current);
        if (currentUrl.hostname.toLowerCase().replace(/\.$/, '') !== domain || currentUrl.protocol !== 'https:') break;
        const response = await withTimeout(signal => fetch(current, { redirect: 'manual', signal, cf: { cacheTtl: 0 } }), FETCH_TIMEOUT_MS);
        blocks.push(formatBlock(response.status, response.statusText, response.headers));
        if (!REDIRECTS.has(response.status)) break;
        const location = response.headers.get('location');
        if (!location) break;
        try { current = new URL(location, current).href; } catch { break; }
      }
    } catch {
      return new Response('No se pudo completar la consulta HTTP al dominio.', { status: 502, headers: cors });
    }
    if (!blocks.length) return new Response('No se obtuvo respuesta del dominio.', { status: 502, headers: cors });
    return new Response(blocks.join('\r\n'), { headers: { ...cors, 'Content-Type': 'text/plain; charset=utf-8' } });
  }
};
