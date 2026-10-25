const V="go-v12",SHELL=["./","index.html","manifest.webmanifest","apple-touch-icon.png","icon-512.png","costume-images.json"];
self.addEventListener("install",e=>{e.waitUntil(caches.open(V).then(c=>Promise.all(SHELL.map(u=>c.add(u).catch(()=>{})))).then(()=>self.skipWaiting()))});
self.addEventListener("activate",e=>{e.waitUntil(caches.keys().then(k=>Promise.all(k.filter(x=>x!==V&&x!=="go-img").map(x=>caches.delete(x)))).then(()=>clients.claim()))});
const fresh=(r)=>fetch(r).then(n=>{const cp=n.clone();if(n.ok)caches.open(V).then(c=>c.put(r,cp));return n}).catch(()=>caches.match(r));
self.addEventListener("fetch",e=>{const r=e.request;if(r.method!=="GET")return;const u=new URL(r.url);
if(u.origin!==location.origin&&/\.png$/.test(u.pathname)){e.respondWith(caches.open("go-img").then(async c=>{const m=await c.match(r);if(m)return m;try{const n=await fetch(r);if(n.ok||n.type==="opaque")c.put(r,n.clone());return n}catch(x){return Response.error()}}));return}
if(u.origin===location.origin){e.respondWith(fresh(r).then(m=>m||caches.match("index.html")));return}
if(u.hostname==="pogoapi.net"){e.respondWith(fresh(r))}});
