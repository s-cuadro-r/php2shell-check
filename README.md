# PHP2Shell Check

Formulario público: https://s-cuadro-r.github.io/php2shell-check/

Ingresá un dominio y seleccioná **Verificar**. El servicio consulta únicamente la dirección principal del sitio por HTTPS mediante solicitudes HTTP normales y busca una versión declarada de PHP.

## Resultados

- **Versión potencialmente afectada:** la versión declarada es anterior a la corrección de su rama. El proveedor puede haber aplicado un parche sin cambiar la versión base; verificá el paquete real.
- **Versión corregida declarada:** el dato publicado coincide con una versión corregida de una rama conocida. La cabecera puede ser inexacta y no verifica todos los servidores que atienden el dominio.
- **No se pudo determinar:** versión oculta, respuesta inaccesible o evidencia insuficiente. No equivale a “seguro”.

No se ejecutan exploits ni se provocan errores en los servidores. No se guardan historiales de consultas en la aplicación. La infraestructura puede mantener registros operativos de acceso.

El aviso oficial de PHP del **21 de octubre de 2026** fija las correcciones en **8.2.35, 8.3.36, 8.4.27 y 8.5.12**. Esta tabla debe revisarse al actualizar el verificador. Para confirmar el parche, revisá el PHP que atiende las solicitudes y los paquetes de su proveedor.

Fuente: https://www.php.net/archive/2026.php#2026-10-21-1

## Alojamiento

Este repositorio contiene la página estática de GitHub Pages. El servicio de consulta se aloja por separado en `https://php2shell-check-api.softbloom11.chatgpt.site/api/check`; GitHub Pages no ejecuta código del servidor. No hay credenciales en el navegador.

Se aceptan dominios públicos con HTTPS. Se rechazan direcciones IP, destinos privados, credenciales, puertos personalizados y rutas. Las redirecciones solo se siguen dentro del mismo dominio y bajo límites de tiempo y cantidad.
