/**
 * Svelte for Frasil's stores: {@link readable} gives a store of the Svelte store contract, which
 * `$store` reads in a component, in Svelte 4 and 5 alike. It imports nothing from Svelte.
 *
 * ```svelte
 * <script>
 *   import { readable } from "@frasil/client/svelte";
 *   export let records;
 *   const tasks = readable(records.observeRows("tasks"));
 * </script>
 * {#if $tasks.status === "ready"}{$tasks.value.size} tasks{/if}
 * ```
 *
 * @module
 */

import type { Observable, Snapshot } from "./observe.js";

export type { Observable, Snapshot, Status } from "./observe.js";

/** A store of the Svelte store contract. */
export interface Readable<T> {
  /** Calls `run` with the value now, then with each new one; returns the function that stops it. */
  subscribe(run: (value: T) => void): () => void;
}

/** The store's snapshots, as a Svelte store. */
export function readable<T>(store: Observable<T>): Readable<Snapshot<T>> {
  return {
    subscribe(run) {
      run(store.get());
      return store.subscribe(() => run(store.get()));
    },
  };
}
