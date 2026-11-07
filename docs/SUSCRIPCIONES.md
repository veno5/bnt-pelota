# BNT Pelota · Suscripciones manuales (preparación)
La aplicación original sigue pública hasta que el administrador valide los permisos comerciales de MLB/LIDOM y decida activar el acceso restringido.
El sistema está en la MISMA instalación Cloudflare Pages "bnt-pelota". No se creó otra aplicación.

## Requisitos para terminar la configuración
1. En Cloudflare > Workers & Pages > D1 SQL Database, crear una base llamada bnt-pelota-clientes.
2. En Workers & Pages > bnt-pelota > Settings > Bindings, agregar la base D1 con el nombre exacto DB; confirmar y redeploy.
3. En Workers & Pages > bnt-pelota > Settings > Variables and Secrets, agregar una variable secreta BNT_ADMIN_PASSWORD con contraseña privada de al menos 12 caracteres; redeploy.
4. Al configurar la base, el backend crea automáticamente las tablas listadas en database/bnt-pelota-d1.sql en la primera llamada.
5. Usar /registro.html para registrar clientes, y /admin.html para registrar transferencias, ver pendientes y vencimientos, y suspender/habilitar clientes.

Las pantallas todavía NO se anuncian en la portada: no promocionar pagos hasta que se prueben registro, inicio de sesión y base de datos, y se aclare la autorización comercial de los datos.
No se debe guardar la contraseña en GitHub ni compartirla en ChatGPT. La administración de cobros funciona solo después de confirmar manualmente cada transferencia. No hay integración bancaria aún.
