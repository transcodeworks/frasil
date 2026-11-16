/**
 * The observed store, against the TypeScript source: it reads once subscribed, takes changes that
 * arrive during a read together, tells subscribers only of a different result, shows what has not
 * arrived as loading, and shares a store by key until its grace period passes.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { FrasilError } from "../../src/errors.js";
import { asyncSource, observe, sharedStore, structurallyEqual } from "../../src/observe.js";

/** A change source the test drives. */
function source() {
  const wakes = new Set<() => void>();
  return {
    changes: (wake: () => void) => {
      wakes.add(wake);
      return () => wakes.delete(wake);
    },
    change: () => {
      for (const wake of wakes) wake();
    },
    get following() {
      return wakes.size;
    },
  };
}

const settle = () => new Promise((resolve) => setTimeout(resolve, 0));

afterEach(() => {
  vi.useRealTimers();
});

describe("structural equality", () => {
  it("compares contents, not references", () => {
    expect(structurallyEqual({ a: [1, { b: 2n }] }, { a: [1, { b: 2n }] })).toBe(true);
    expect(structurallyEqual(new Map([["k", { x: 1 }]]), new Map([["k", { x: 1 }]]))).toBe(true);
    expect(structurallyEqual(new Uint8Array([1, 2]), new Uint8Array([1, 2]))).toBe(true);
    expect(structurallyEqual(new Uint8Array([1, 2]), new Uint8Array([1, 3]))).toBe(false);
    expect(structurallyEqual({ a: 1 }, { a: 1, b: undefined })).toBe(false);
    expect(structurallyEqual([1], { 0: 1 })).toBe(false);
    expect(structurallyEqual(Number.NaN, Number.NaN)).toBe(true);
  });
});

describe("observe", () => {
  it("reads once subscribed, and tells only of different results", async () => {
    const feed = source();
    let value = { n: 1 };
    let reads = 0;
    const store = observe(async () => {
      reads += 1;
      return value;
    }, feed.changes);
    expect(store.get().status).toBe("loading");
    await settle();
    expect(reads).toBe(0);
    const heard = vi.fn();
    const stop = store.subscribe(heard);
    await settle();
    expect(store.get()).toEqual({ status: "ready", value: { n: 1 } });
    expect(heard).toHaveBeenCalledTimes(1);
    const first = store.get();

    value = { n: 1 };
    feed.change();
    await settle();
    expect(reads).toBe(2);
    expect(store.get()).toBe(first);
    expect(heard).toHaveBeenCalledTimes(1);

    value = { n: 2 };
    feed.change();
    await settle();
    expect(store.get().value).toEqual({ n: 2 });
    expect(heard).toHaveBeenCalledTimes(2);
    stop();
  });

  it("takes changes that arrive during a read together", async () => {
    const feed = source();
    let release: () => void = () => {};
    let reads = 0;
    const store = observe(
      () =>
        new Promise<number>((resolve) => {
          reads += 1;
          release = () => resolve(reads);
        }),
      feed.changes,
      { gracePeriod: 0 },
    );
    const stop = store.subscribe(() => {});
    await settle();
    expect(reads).toBe(1);
    for (let i = 0; i < 10; i += 1) feed.change();
    release();
    await settle();
    expect(reads).toBe(2);
    release();
    await settle();
    expect(reads).toBe(2);
    expect(store.get().value).toBe(2);
    stop();
    expect(feed.following).toBe(0);
  });

  it("shows what has not arrived as loading, and other failures as errors", async () => {
    const feed = source();
    let fail: Error | undefined = new FrasilError("unknown_stream", "not yet");
    const store = observe(async () => {
      if (fail) throw fail;
      return "here";
    }, feed.changes);
    const stop = store.subscribe(() => {});
    await settle();
    expect(store.get()).toEqual({ status: "loading", value: undefined });
    fail = undefined;
    feed.change();
    await settle();
    expect(store.get()).toEqual({ status: "ready", value: "here" });
    const broken = new FrasilError("store", "the disk is full");
    fail = broken;
    feed.change();
    await settle();
    expect(store.get()).toEqual({ status: "failed", value: "here", error: broken });
    stop();
  });

  it("keeps an undefined result ready without telling again", async () => {
    const feed = source();
    const store = observe(async () => undefined, feed.changes);
    const heard = vi.fn();
    const stop = store.subscribe(heard);
    await settle();
    feed.change();
    await settle();
    expect(store.get().status).toBe("ready");
    expect(heard).toHaveBeenCalledTimes(1);
    stop();
  });
});

describe("shared stores", () => {
  it("are one store per key while followed, and for the grace period after", async () => {
    vi.useFakeTimers();
    const owner = {};
    const feed = source();
    const make = () => sharedStore(owner, "k", async () => 1, feed.changes);
    const first = make();
    expect(make()).toBe(first);
    const stop = first.subscribe(() => {});
    expect(feed.following).toBe(1);
    stop();
    expect(feed.following).toBe(1);
    expect(make()).toBe(first);
    const again = first.subscribe(() => {});
    await vi.advanceTimersByTimeAsync(10_000);
    expect(feed.following).toBe(1);
    again();
    await vi.advanceTimersByTimeAsync(5_000);
    expect(feed.following).toBe(0);
    expect(make()).not.toBe(first);
  });
});

describe("change sources", () => {
  it("show a feed that could not start as failed", async () => {
    const refused = new FrasilError("unknown_space", "gone");
    const store = observe(
      async () => 1,
      asyncSource(() => Promise.reject(refused)),
    );
    const stop = store.subscribe(() => {});
    await settle();
    await settle();
    expect(store.get().status).toBe("failed");
    expect(store.get().error).toBe(refused);
    stop();
  });
});
