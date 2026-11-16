#!/usr/bin/env node
// Fetch the Wycheproof files `docs/spec/vectors/crypto.json` pins into
// the reference script's git-ignored cache, where `frasil-crypto`'s
// `wycheproof` tests read them. The reference script
// (`docs/spec/reference/generate.py`) fetches the same files to the same
// place; this does it without Python, for CI and for a fresh checkout.
//
// A file already in the cache is not fetched again. Every file is checked
// against its pinned SHA-256, and a file that differs is refused and removed.

import { createHash } from "node:crypto";
import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const vectors = JSON.parse(await readFile(join(root, "docs/spec/vectors/crypto.json"), "utf8"));
const { commit, files } = vectors.wycheproof;
const cache = join(root, "docs/spec/reference/.cache/wycheproof", commit);
const ATTEMPTS = 3;

async function fetched(path) {
  const url = `https://raw.githubusercontent.com/C2SP/wycheproof/${commit}/${path}`;
  let last;
  for (let attempt = 1; attempt <= ATTEMPTS; attempt += 1) {
    try {
      const response = await fetch(url, { signal: AbortSignal.timeout(60_000) });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      return Buffer.from(await response.arrayBuffer());
    } catch (error) {
      last = error;
    }
  }
  throw new Error(`could not fetch ${url}: ${last?.message ?? last}`);
}

for (const [path, { sha256 }] of Object.entries(files)) {
  const file = join(cache, path);
  let contents = await readFile(file).catch(() => null);
  const cached = contents !== null;
  if (!cached) contents = await fetched(path);
  const digest = createHash("sha256").update(contents).digest("hex");
  if (digest !== sha256) {
    if (cached) await rm(file);
    console.error(`${path}: SHA-256 ${digest} is not the pinned ${sha256}`);
    process.exit(1);
  }
  if (!cached) {
    await mkdir(dirname(file), { recursive: true });
    await writeFile(file, contents);
  }
  console.log(`${path}: ${cached ? "in the cache" : "fetched"}, SHA-256 matches`);
}
