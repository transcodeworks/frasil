// @ts-nocheck: a worker's globals, and an import by the URL the test origin serves.
// A dedicated worker that holds a `MediaServer`, as an application whose client runs in a worker
// does: the page hands it each port to the service worker, and it mints URLs when asked. What it
// serves is a pattern of 3,000,000 bytes that the test can name again, read through a stand-in
// for a blob stream's reader, so that the worker needs no device.
import { MediaServer } from "/dist/media.js";

const SIZE = 3_000_000;
const media = new MediaServer();
const blobs = {
  openReader: async () => ({
    fetchSize: async () => SIZE,
    read: async (offset, length) => {
      const piece = new Uint8Array(Math.max(0, Math.min(length, SIZE - offset)));
      for (let index = 0; index < piece.length; index += 1) {
        piece[index] = ((offset + index) * 31 + 7) & 0xff;
      }
      return piece;
    },
    close: async () => {},
  }),
};

self.addEventListener("message", ({ data }) => {
  if (data.mediaPort) media.attach(data.mediaPort);
  else if (data === "mint") self.postMessage({ url: media.url(blobs, "pattern") });
});
