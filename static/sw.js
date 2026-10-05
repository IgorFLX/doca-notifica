self.addEventListener("push", (event) => {
  let data = { title: "Chamada de doca", body: "Va para a doca.", url: "/motorista", tag: "chamada-doca" };
  if (event.data) {
    try {
      data = { ...data, ...event.data.json() };
    } catch (e) {
      data.body = event.data.text();
    }
  }
  event.waitUntil(
    (async () => {
      if (data.tipo === "operador") {
        const janelas = await clients.matchAll({ type: "window", includeUncontrolled: true });
        const painelVisivel = janelas.some(
          (c) => c.visibilityState === "visible" && new URL(c.url).pathname === "/"
        );
        if (painelVisivel) return;
      }
      await self.registration.showNotification(data.title, {
        body: data.body,
        vibrate: [400, 200, 400, 200, 400],
        tag: data.tag,
        renotify: true,
        requireInteraction: true,
        data: { url: data.url },
      });
    })()
  );
});

self.addEventListener("notificationclick", (event) => {
  event.notification.close();
  const alvo = (event.notification.data && event.notification.data.url) || "/";
  event.waitUntil(
    clients.matchAll({ type: "window", includeUncontrolled: true }).then((janelas) => {
      for (const c of janelas) {
        if (new URL(c.url).pathname === alvo && "focus" in c) return c.focus();
      }
      if (clients.openWindow) return clients.openWindow(alvo);
    })
  );
});
