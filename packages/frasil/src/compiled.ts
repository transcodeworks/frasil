/**
 * Internal, for the entry `@frasil/client/module` only: the compiled WebAssembly module the
 * application gives to `load`, which that entry's copy of the runtime waits for before it
 * instantiates it. The default entry never imports this file.
 *
 * @internal
 * @module
 */

let supply: (module: WebAssembly.Module) => void = () => {};

/** The module `load` was given; pending until then. */
export const compiled: Promise<WebAssembly.Module> = new Promise((resolve) => {
  supply = resolve;
});

/** Gives the module. Only the first call counts. */
export function provide(module: WebAssembly.Module): void {
  supply(module);
}
