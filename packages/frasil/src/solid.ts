/**
 * Solid for Frasil's stores: {@link createObserved} gives an accessor of a store's latest
 * snapshot, which tracks it, and stops following it with its owner.
 *
 * ```tsx
 * import { createObserved } from "@frasil/client/solid";
 *
 * function Tasks(props: { records: Records }) {
 *   const tasks = createObserved(props.records.observeRows("tasks"));
 *   return <Show when={tasks().status === "ready"}>{tasks().value!.size} tasks</Show>;
 * }
 * ```
 *
 * @module
 */

import { type Accessor, from } from "solid-js";
import type { Observable, Snapshot } from "./observe.js";

export type { Observable, Snapshot, Status } from "./observe.js";

/** An accessor of the store's latest snapshot. Call it in a reactive scope, under an owner. */
export function createObserved<T>(store: Observable<T>): Accessor<Snapshot<T>> {
  const latest = from<Snapshot<T>>((set) => {
    set(() => store.get());
    return store.subscribe(() => set(() => store.get()));
  });
  return () => latest() ?? store.get();
}
