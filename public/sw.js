// El service worker solamente guarda la portada y los iconos, nunca los datos privados o deportivos.
const CACHE="bnt-pelota-shell-icon-2026-11-07-v2";
const ASSETS=["/","/manifest.webmanifest?v=2026-11-07-bnt2","/icon-192.png?v=bnt-2026-11-icono2","/icon-512.png?v=bnt-2026-11-icono2","/apple-touch-icon.png?v=bnt-2026-11-icono2","/favicon-64.png?v=bnt-2026-11-icono2"];
self.addEventListener("install",event=>event.waitUntil(caches.open(CACHE).then(cache=>cache.addAll(ASSETS)).then(()=>self.skipWaiting())));
self.addEventListener("activate",event=>event.waitUntil(caches.keys().then(keys=>Promise.all(keys.filter(k=>k.startsWith("bnt-pelota-")&&k!==CACHE).map(k=>caches.delete(k)))).then(()=>self.clients.claim())));
self.addEventListener("fetch",event=>{
 const req=event.request,url=new URL(req.url);
 if(req.method!=="GET"||url.origin!==self.location.origin||url.pathname.startsWith("/api/"))return;
 if(req.mode==="navigate"){
  if(url.pathname!=="/")return;
  event.respondWith(fetch(req).catch(async()=>await caches.match("/")||Response.error()));
  return;
 }
 if(/^\/(?:icon-192|icon-512|apple-touch-icon|favicon-64)\.png$/.test(url.pathname)){
  event.respondWith(caches.match(req).then(cached=>cached||fetch(req)));
 }
});
