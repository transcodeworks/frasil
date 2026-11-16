/**
 * Internal: where the WebAssembly module comes from, for the entries `@frasil/client/embedded`
 * and `@frasil/client/index/embedded`: its bytes, inlined in the package as base64, for an
 * application that cannot host a `.wasm` file. They are decoded and instantiated with
 * `WebAssembly.instantiate` once, when the package is first imported.
 *
 * @internal
 * @module
 */

import type { Source } from "./engine.js";
import base64 from "./wasm/frasil_wasm_base64.js";

function decode(text: string): Uint8Array<ArrayBuffer> {
  const native = (Uint8Array as { fromBase64?: (text: string) => Uint8Array<ArrayBuffer> })
    .fromBase64;
  if (native) return native(text);
  const binary = atob(text);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) bytes[index] = binary.charCodeAt(index);
  return bytes;
}

/** The module's bytes. */
export const engine: Promise<Source> = Promise.resolve(decode(base64));
