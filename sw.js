/* RemoteLink Service Worker - 离线缓存 */
var CACHE = 'remotelink-v2';
var ASSETS = [
  './index.html',
  './crypto.js',
  './manifest.json'
];

self.addEventListener('install', function(e){
  e.waitUntil(
    caches.open(CACHE).then(function(c){
      return c.addAll(ASSETS).catch(function(){});
    }).then(function(){ return self.skipWaiting(); })
  );
});

self.addEventListener('activate', function(e){
  e.waitUntil(
    caches.keys().then(function(keys){
      return Promise.all(keys.map(function(k){
        if(k !== CACHE) return caches.delete(k);
      }));
    }).then(function(){ return self.clients.claim(); })
  );
});

self.addEventListener('fetch', function(e){
  var url = e.request.url;
  // 只缓存同源静态资源；API 请求不缓存
  if(e.request.method !== 'GET') return;
  if(url.indexOf('/api/') >= 0) return;
  if(url.indexOf('api.deepseek.com') >= 0) return;

  e.respondWith(
    caches.match(e.request).then(function(hit){
      var net = fetch(e.request).then(function(resp){
        if(resp && resp.status === 200 && resp.type === 'basic'){
          var copy = resp.clone();
          caches.open(CACHE).then(function(c){ c.put(e.request, copy); });
        }
        return resp;
      }).catch(function(){
        return hit || new Response('离线', {status:503});
      });
      return hit || net;
    })
  );
});
