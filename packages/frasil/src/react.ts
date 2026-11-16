/**
 * React for Frasil's stores: {@link useObserved} renders a store's latest snapshot, through
 * `useSyncExternalStore`, and renders again when it changes.
 *
 * ```tsx
 * import { useObserved } from "@frasil/client/react";
 *
 * function Tasks({ records }: { records: Records }) {
 *   const tasks = useObserved(records.observeRows("tasks"));
 *   if (tasks.status === "loading") return <Spinner />;
 *   return <List rows={tasks.value} />;
 * }
 * ```
 *
 * The prebuilt stores (`records.observeRows`, `drive.observe`, …) return the same store for the
 * same thing, so they may be asked for during render. Keep a store from `observe` or
 * `space.observe` in `useMemo`, since each call makes a new one.
 *
 * @module
 */

import { useSyncExternalStore } from "react";
import type { Observable, Snapshot } from "./observe.js";

export type { Observable, Snapshot, Status } from "./observe.js";

/** The store's latest snapshot; the component renders again when it changes. */
export function useObserved<T>(store: Observable<T>): Snapshot<T> {
  return useSyncExternalStore(store.subscribe, store.get, store.get);
}
