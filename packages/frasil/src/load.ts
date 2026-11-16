/**
 * The entry `@frasil/client/module`, for a host that imports `.wasm` files as compiled
 * `WebAssembly.Module`s and refuses to compile WebAssembly from bytes at run time. The default
 * entry inlines the module's bytes and instantiates them when it is imported; this one ships the
 * bare module, `@frasil/client/module/frasil_wasm.wasm`, and instantiates the `WebAssembly.Module`
 * the application gives {@link load}. What `load` returns is the default entry's API.
 *
 * ```ts
 * import wasm from "@frasil/client/module/frasil_wasm.wasm";
 * import { load } from "@frasil/client/module";
 *
 * const frasil = await load(wasm);
 * ```
 *
 * A Cloudflare Worker verifies requests that devices signed:
 *
 * ```ts
 * await load(wasm);
 * const { person, device } = await verifySignedRequest(request, {
 *   audience: "https://api.example.org",
 *   subject,
 *   deviceLists,
 *   nonces,
 * });
 * ```
 *
 * @module
 */

import { provide } from "./compiled.js";
import { FrasilError } from "./errors.js";
import type { DeviceLists, NonceStore, VerifiedRequest } from "./requests.js";

export type * from "./index.js";

/** The API, once {@link load} was called. */
let loaded: Promise<typeof import("./index.js")> | undefined;

/**
 * Instantiates the package's WebAssembly module from `module`, compiled already, and returns the
 * package's API. Later calls return the same API, whatever module they are given.
 *
 * @throws {@link FrasilError} `invalid_input` if `module` is not a `WebAssembly.Module`.
 */
export async function load(module: WebAssembly.Module): Promise<typeof import("./index.js")> {
  if (!(module instanceof WebAssembly.Module)) {
    throw new FrasilError(
      "invalid_input",
      "load takes the package's WebAssembly module, compiled: a WebAssembly.Module.",
    );
  }
  provide(module);
  loaded ??= import("./index.js");
  return loaded;
}

/**
 * Verifies a request a device signed with `Device.signRequest`, in a Cloudflare Worker or another
 * server: see the default entry's `verifySignedRequest`. Call {@link load} first.
 *
 * @throws {@link FrasilError} `not_allowed` before {@link load} was called.
 */
export async function verifySignedRequest(
  request: Request,
  options: { audience: string; subject: string; deviceLists: DeviceLists; nonces: NonceStore },
): Promise<VerifiedRequest> {
  if (loaded === undefined) {
    throw new FrasilError(
      "not_allowed",
      "verifySignedRequest needs the package's WebAssembly module: call load(wasm) first.",
    );
  }
  return (await loaded).verifySignedRequest(request, options);
}
