// @ts-nocheck: a service worker's globals, and an import by the URL the test origin serves.
// A service worker of an application's own, which answers its own requests and messages and
// hands the media helper's to `handleMedia`, under a prefix of its own given without the slash
// it ends with. A module script: it imports the handler.
import { handleMedia } from "/dist/media-worker.js";

const PREFIX = "/played";

self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", (event) => event.waitUntil(self.clients.claim()));
self.addEventListener("fetch", (event) => {
  if (handleMedia(event, PREFIX)) return;
  if (new URL(event.request.url).pathname === "/composed/ping") {
    event.respondWith(new Response("pong", { headers: { "x-composed": "yes" } }));
  }
});
self.addEventListener("message", (event) => {
  if (handleMedia(event, PREFIX)) return;
  if (event.data === "ping") event.source.postMessage("pong");
});
