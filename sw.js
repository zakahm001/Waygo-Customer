// Trollhättan Cab — Service Worker v1.0
const CACHE_NAME = 'thtcab-driver-v1';

self.addEventListener('install', function(e) {
  self.skipWaiting();
});

self.addEventListener('activate', function(e) {
  e.waitUntil(self.clients.claim());
});

// Handle push notifications
self.addEventListener('push', function(e) {
  var data = {};
  try { data = e.data.json(); } catch(err) { data = { title: '🚖 Ny bokning!', body: 'Tryck för att se detaljer' }; }
  var options = {
    body: data.body || 'Ny bokning tilldelad',
    icon: '/logo.png',
    badge: '/logo.png',
    vibrate: [800, 200, 400, 200, 800],
    requireInteraction: true,
    tag: 'thtcab-booking',
    data: { url: '/driver' }
  };
  e.waitUntil(self.registration.showNotification(data.title || '🚨 Ny bokning!', options));
});

// Handle notification click — open driver app
self.addEventListener('notificationclick', function(e) {
  e.notification.close();
  e.waitUntil(
    self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then(function(clients) {
      for (var i = 0; i < clients.length; i++) {
        if (clients[i].url.includes('/driver')) {
          return clients[i].focus();
        }
      }
      return self.clients.openWindow('/driver');
    })
  );
});

// Keep alive — respond to fetch
self.addEventListener('fetch', function(e) {
  // Pass through all requests
});
