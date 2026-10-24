# PHP2Shell Check

Formulario público: https://s-cuadro-r.github.io/php2shell-check/

Ingresá un dominio y seleccioná **Verificar**. La página consulta las cabeceras públicas mediante un endpoint propio desplegado en Cloudflare Workers (`worker/header-check.js`), después de comprobar su resolución DNS pública mediante Cloudflare DNS over HTTPS. No se ejecutan exploits ni se provocan errores en los servidores.

También existe la pestaña **Pegar cabeceras**, para analizar sin ninguna consulta de red: pegás vos mismo la salida de `curl -i -L` de un dominio y se evalúa 100% en el navegador.

## Resultados

- **Versión potencialmente afectada:** la versión declarada es anterior a la corrección de su rama. Un proveedor puede haber aplicado un parche sin cambiar la versión base; verificá el paquete real.
- **Versión corregida declarada:** el dato publicado coincide con una versión corregida de una rama conocida. La cabecera puede ser inexacta y no verifica todos los servidores que atienden el dominio.
- **No se pudo determinar:** versión oculta, respuesta inaccesible o evidencia insuficiente. No equivale a “seguro”.

Si las cabeceras públicas muestran señales de un WAF o CDN conocido (Cloudflare, Akamai, Sucuri, Imperva/Incapsula, Amazon CloudFront, Fastly o Azure Front Door), el resultado lo indica como evidencia adicional. En ese caso, la versión u otra información observada puede corresponder al borde de esa red y no al servidor de origen; cualquier veredicto para ese dominio debe confirmarse directamente en el servidor que ejecuta la aplicación.

El aviso oficial de PHP del **21 de octubre de 2026** fija las correcciones en **8.2.35, 8.3.36, 8.4.27 y 8.5.12**. Revisá esta tabla cuando cambie el aviso. Para confirmar el parche, revisá el PHP que atiende las solicitudes y los paquetes de su proveedor.

Fuente: https://www.php.net/archive/2026.php#2026-10-21-1

## Alojamiento y datos

Esta página funciona como sitio estático de GitHub Pages, sin claves ni credenciales en el navegador. Los dominios consultados se envían a Cloudflare: a su DNS público para resolver el dominio, y a un Worker propio (cuenta de Cloudflare dedicada a este proyecto) para obtener las cabeceras HTTP. Son servicios de Cloudflare, con su propia política de privacidad y disponibilidad.

La aplicación no guarda un historial de consultas. GitHub y Cloudflare pueden mantener registros operativos propios de su infraestructura. No introduzcas dominios que no quieras que esos servicios vean.

Se aceptan dominios públicos con HTTPS. Se rechazan direcciones IP, destinos privados conocidos, credenciales, puertos personalizados y rutas. El endpoint puede seguir redirecciones dentro del mismo dominio; si la respuesta indica otro dominio, la evaluación se considera indeterminada. La resolución pública previa no fija la IP que se use luego.

## Cuota de consultas

Las consultas se resuelven contra un Worker propio en la capa gratuita de Cloudflare Workers: **100.000 solicitudes por día**, de uso exclusivo de este proyecto, sin compartirse con ningún otro sitio ni visitante externo. No hay límite práctico para el uso normal de esta página.

El Worker (`worker/header-check.js`) se despliega con el workflow de GitHub Actions `.github/workflows/deploy-worker.yml` (disparo manual desde la pestaña **Actions**), usando un token de Cloudflare guardado como secreto del repositorio — no requiere ninguna máquina ni instalación local.

## Archivos

- `index.html`: formulario y presentación accesible de resultados.
- `checker.js`: validación, consulta pasiva y evaluación de cabeceras.
- `worker/header-check.js`: endpoint propio (Cloudflare Worker) que responde con las cabeceras públicas del dominio consultado.
- `worker/wrangler.toml`: configuración de despliegue del Worker.
- `.github/workflows/deploy-worker.yml`: despliega o redespliega el Worker desde GitHub Actions.
- `.nojekyll`: publicación estática sin procesamiento de Jekyll.

La página compara versiones declaradas con los umbrales verificados. No certifica la seguridad general de los sitios, la ausencia de intrusiones ni la explotación de las vulnerabilidades.
