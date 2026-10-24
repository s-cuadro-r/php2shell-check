# PHP2Shell Check

Formulario público: https://s-cuadro-r.github.io/php2shell-check/

Ingresá un dominio y seleccioná **Verificar**. La página consulta las cabeceras públicas mediante la API de [HackerTarget](https://hackertarget.com/http-header-check/), después de comprobar su resolución DNS pública mediante Cloudflare DNS over HTTPS. No se ejecutan exploits ni se provocan errores en los servidores.

## Resultados

- **Versión potencialmente afectada:** la versión declarada es anterior a la corrección de su rama. Un proveedor puede haber aplicado un parche sin cambiar la versión base; verificá el paquete real.
- **Versión corregida declarada:** el dato publicado coincide con una versión corregida de una rama conocida. La cabecera puede ser inexacta y no verifica todos los servidores que atienden el dominio.
- **No se pudo determinar:** versión oculta, respuesta inaccesible o evidencia insuficiente. No equivale a “seguro”.

Si las cabeceras públicas muestran señales de un WAF o CDN conocido (Cloudflare, Akamai, Sucuri, Imperva/Incapsula, Amazon CloudFront, Fastly o Azure Front Door), el resultado lo indica como evidencia adicional. En ese caso, la versión u otra información observada puede corresponder al borde de esa red y no al servidor de origen; cualquier veredicto para ese dominio debe confirmarse directamente en el servidor que ejecuta la aplicación.

El aviso oficial de PHP del **21 de octubre de 2026** fija las correcciones en **8.2.35, 8.3.36, 8.4.27 y 8.5.12**. Revisá esta tabla cuando cambie el aviso. Para confirmar el parche, revisá el PHP que atiende las solicitudes y los paquetes de su proveedor.

Fuente: https://www.php.net/archive/2026.php#2026-10-21-1

## Alojamiento y datos

Esta página funciona como sitio estático de GitHub Pages, sin claves ni credenciales en el navegador. Los dominios consultados se envían a Cloudflare para resolver DNS y a HackerTarget para obtener las cabeceras HTTP. Son servicios externos con sus propias políticas de privacidad y disponibilidad. HackerTarget impone cuotas de consultas; al agotarse, la página muestra un error y permite volver a intentar más tarde.

La aplicación no guarda un historial de consultas. GitHub y los proveedores pueden mantener registros operativos. No introduzcas dominios que no quieras compartir con estos proveedores.

Se aceptan dominios públicos con HTTPS. Se rechazan direcciones IP, destinos privados conocidos, credenciales, puertos personalizados y rutas. HackerTarget puede seguir redirecciones; si la respuesta indica otro dominio, la evaluación se considera indeterminada. La resolución pública previa no fija la IP que el proveedor usará posteriormente.

## Cuota de consultas y endpoint propio

Por defecto, la página usa la API gratuita de [HackerTarget](https://hackertarget.com/http-header-check/), que impone una cuota chica **compartida por IP entre todos los visitantes**. Con uso moderado es fácil alcanzarla y recibir "HackerTarget alcanzó su cuota de consultas".

Para no depender de esa cuota compartida, podés desplegar tu propio reemplazo pasivo bajo tu cuenta gratuita de Cloudflare Workers (100.000 requests/día, propios, sin compartir con nadie más):

```sh
npm install -g wrangler
wrangler login
cd worker && wrangler deploy
```

Esto te da una URL del tipo `https://php2shell-headers.<tu-cuenta>.workers.dev`. Pegala como valor de `SELF_HOSTED_ENDPOINT` al principio de `checker.js` y volvé a publicar la página: a partir de ahí, todas las consultas pasan por tu propio Worker en vez de por HackerTarget. El Worker (`worker/header-check.js`) hace exactamente la misma comprobación pasiva —mismo chequeo de dominio público, misma validación anti-SSRF, mismas cabeceras leídas— solo que corriendo bajo tu propia cuenta.

## Archivos

- `index.html`: formulario y presentación accesible de resultados.
- `checker.js`: validación, consulta pasiva y evaluación de cabeceras.
- `worker/header-check.js`: endpoint propio opcional (Cloudflare Worker) para no depender de la cuota compartida de HackerTarget.
- `worker/wrangler.toml`: configuración de despliegue del Worker.
- `.nojekyll`: publicación estática sin procesamiento de Jekyll.

La página compara versiones declaradas con los umbrales verificados. No certifica la seguridad general de los sitios, la ausencia de intrusiones ni la explotación de las vulnerabilidades.
