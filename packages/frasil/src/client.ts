/**
 * The entry `@frasil/client/client`: {@link IndexClient} alone, for a page that only queries and
 * watches the index a worker serves. It loads no WebAssembly, and neither does anything it
 * imports; the worker opens the device and the index with `@frasil/client/index`.
 *
 * ```ts
 * import { IndexClient } from "@frasil/client/client";
 *
 * const index = new IndexClient(worker);
 * const open = index.watch("SELECT title FROM task WHERE done = 0");
 * ```
 *
 * @module
 */

export { FrasilError } from "./errors.js";
export { IndexClient } from "./index-client.js";
export type { Observable, Snapshot, Status } from "./observe.js";
