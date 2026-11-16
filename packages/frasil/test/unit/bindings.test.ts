// @vitest-environment jsdom
/**
 * The React, Svelte and Solid bindings, over a store the test drives: each shows the store's
 * latest snapshot, follows it while in use, and stops following when no longer used.
 */
import { act, createElement } from "react";
import { createRoot } from "react-dom/client";
import { createEffect, createRoot as solidRoot } from "solid-js";
import { get } from "svelte/store";
import { describe, expect, it } from "vitest";
import type { Observable, Snapshot } from "../../src/observe.js";
import { useObserved } from "../../src/react.js";
import { createObserved } from "../../src/solid.js";
import { readable } from "../../src/svelte.js";

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

/** A store the test sets. */
function store<T>(initial: Snapshot<T>) {
  let snapshot = initial;
  const listeners = new Set<() => void>();
  const observable: Observable<T> = {
    get: () => snapshot,
    subscribe: (listener) => {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
  };
  return {
    observable,
    set(next: Snapshot<T>) {
      snapshot = next;
      for (const listener of [...listeners]) listener();
    },
    get subscribers() {
      return listeners.size;
    },
  };
}

describe("React", () => {
  it("renders the latest snapshot and unsubscribes on unmount", async () => {
    const tasks = store<string[]>({ status: "loading", value: undefined });
    function Tasks() {
      const now = useObserved(tasks.observable);
      return createElement("p", null, now.status === "ready" ? now.value?.join(",") : now.status);
    }
    const container = document.createElement("div");
    const root = createRoot(container);
    await act(async () => root.render(createElement(Tasks)));
    expect(container.textContent).toBe("loading");
    expect(tasks.subscribers).toBe(1);
    await act(async () => tasks.set({ status: "ready", value: ["a", "b"] }));
    expect(container.textContent).toBe("a,b");
    await act(async () => root.unmount());
    expect(tasks.subscribers).toBe(0);
  });
});

describe("Svelte", () => {
  it("keeps the store contract", () => {
    const tasks = store<number>({ status: "loading", value: undefined });
    const svelte = readable(tasks.observable);
    expect(get(svelte).status).toBe("loading");
    const seen: Snapshot<number>[] = [];
    const stop = svelte.subscribe((value) => seen.push(value));
    tasks.set({ status: "ready", value: 3 });
    expect(seen.map((s) => s.value)).toEqual([undefined, 3]);
    stop();
    expect(tasks.subscribers).toBe(0);
  });
});

describe("Solid", () => {
  it("tracks the snapshot, and stops with its owner", () => {
    const tasks = store<number>({ status: "loading", value: undefined });
    const seen: (number | undefined)[] = [];
    const dispose = solidRoot((dispose) => {
      const now = createObserved(tasks.observable);
      createEffect(() => seen.push(now().value));
      return dispose;
    });
    tasks.set({ status: "ready", value: 1 });
    tasks.set({ status: "ready", value: 2 });
    expect(seen).toEqual([undefined, 1, 2]);
    expect(tasks.subscribers).toBe(1);
    dispose();
    expect(tasks.subscribers).toBe(0);
  });
});
