/**
 * Internal: where the WebAssembly module comes from, for the entry `@frasil/client/module`: the
 * compiled module the application gives to `load`.
 *
 * @internal
 * @module
 */

import { compiled } from "./compiled.js";

/** The module `load` was given; pending until then. */
export const engine: Promise<WebAssembly.Module> = compiled;
