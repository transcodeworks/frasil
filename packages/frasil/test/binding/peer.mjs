// Builds the workspace's peer, `frasil-relay`, and runs it on loopback for the binding's tests:
// on FRASIL_TEST_PEER_PORT, with a fresh data directory, and without the iroh binding (a browser
// reaches a peer over the server binding only). It runs as a separate process: the package and its
// tests link nothing of the peer. It stops on SIGTERM and removes its data.
//
// The peer is a core peer that hosts any space a test creates (FRASIL_EXTENSIONS=none,
// FRASIL_HOSTING=open), unless the environment names other settings, such as
// FRASIL_EXTENSIONS=libraries and FRASIL_OPEN_LIBRARY.
//
//   FRASIL_TEST_PEER_PORT=… node test/binding/peer.mjs
import { execFileSync, spawn } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../../../..", import.meta.url));
const port = Number(process.env.FRASIL_TEST_PEER_PORT ?? 8787);
const targetDir = process.env.CARGO_TARGET_DIR ?? join(root, "target");

const features = process.env.FRASIL_TEST_PEER_FEATURES;
const build = ["build", "--locked", "-p", "frasil-relay", "--bin", "frasil-relay"];
execFileSync("cargo", features ? [...build, "--features", features] : build, {
  cwd: root,
  stdio: ["ignore", "inherit", "inherit"],
});

const data = mkdtempSync(join(tmpdir(), "frasil-relay-"));
const peer = spawn(join(targetDir, "debug", "frasil-relay"), ["serve"], {
  cwd: data,
  stdio: ["ignore", "inherit", "inherit"],
  env: {
    ...process.env,
    FRASIL_EXTENSIONS: process.env.FRASIL_EXTENSIONS ?? "none",
    FRASIL_HOSTING: process.env.FRASIL_HOSTING ?? "open",
    FRASIL_LISTEN: `127.0.0.1:${port}`,
    FRASIL_DATA_DIR: data,
    FRASIL_IROH: "off",
  },
});

const stop = () => peer.kill("SIGTERM");
process.on("SIGTERM", stop);
process.on("SIGINT", stop);
peer.on("exit", (code) => {
  rmSync(data, { recursive: true, force: true });
  process.exit(code ?? 0);
});
