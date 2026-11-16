/**
 * Observed reads: a read that runs again when what it reads changes, as a store that frameworks
 * subscribe to.
 *
 * {@link observe} turns any read into an {@link Observable}: `get()` returns a {@link Snapshot}
 * and `subscribe(listener)` calls `listener` each time it changes. The store reads once its first
 * subscriber arrives, and again after each change of what it watches. Changes that arrive while a
 * read runs are taken together, so that a burst of changes costs one read more, not one per
 * change. Subscribers hear of a new snapshot only when its value differs from the last one,
 * compared structurally, so an unchanged result keeps its reference.
 *
 * The prebuilt stores (`records.observeRows`, `drive.observe`, …) are shared: asking again for
 * the same thing returns the same store while anyone subscribes to it, and for a short grace
 * period after the last one leaves.
 *
 * A store fits React's `useSyncExternalStore` as it is; the entries `@frasil/client/react`,
 * `@frasil/client/svelte` and `@frasil/client/solid` adapt it to each framework.
 *
 * @module
 */

import { FrasilError } from "./errors.js";

/**
 * Where an observed read stands: `"loading"` before its first read finishes and while what it
 * reads has not arrived at this device, `"ready"` once it read what the device holds, `"failed"`
 * when its last read failed for another reason.
 */
export type Status = "loading" | "ready" | "failed";

/** What an observed read gave. A new object only when something in it changed. */
export interface Snapshot<T> {
  readonly status: Status;
  /** What it read: `undefined` while loading, and before any read succeeded. */
  readonly value: T | undefined;
  /** Why its last read failed, under `"failed"`; the value then is the last one read. */
  readonly error?: unknown;
}

/** A store of an observed read: the contract every framework binding builds on. */
export interface Observable<T> {
  /** The latest snapshot: the same object until something in it changes. */
  get(): Snapshot<T>;
  /**
   * Calls `listener` each time the snapshot changes, from now on. The first subscriber starts the
   * store reading. Returns the function that stops it.
   */
  subscribe(listener: () => void): () => void;
}

/**
 * The changes an observed read follows: a function that starts following, calls `wake` after
 * each change that may change the read's result, calls `fail` if it cannot follow, and returns the
 * function that stops following.
 */
export type ChangeSource = (wake: () => void, fail: (error: unknown) => void) => () => void;

/** How {@link observe} behaves. */
export interface ObserveOptions<T> {
  /** Whether two results are the same, so that subscribers are not told. Structural by default. */
  readonly equals?: (a: T, b: T) => boolean;
  /**
   * How long, in milliseconds, the store keeps following after its last subscriber left, so that
   * one that comes back soon finds it current. 5,000 by default.
   */
  readonly gracePeriod?: number;
}

/** The grace period after the last subscriber leaves. */
const GRACE = 5_000;

/** Whether an error says that what a read needs has not arrived at this device yet. */
export function notArrived(error: unknown): boolean {
  return (
    error instanceof Error &&
    "code" in error &&
    (error.code === "unknown_stream" || error.code === "missing")
  );
}

/**
 * Whether two values are the same, structurally: primitives by `Object.is`, and arrays, plain
 * objects, `Map`s, `Set`s, typed arrays and `Date`s by their contents. Other objects by identity.
 */
export function structurallyEqual(a: unknown, b: unknown): boolean {
  if (Object.is(a, b)) return true;
  if (typeof a !== "object" || typeof b !== "object" || a === null || b === null) return false;
  if (Object.getPrototypeOf(a) !== Object.getPrototypeOf(b)) return false;
  if (Array.isArray(a)) {
    const other = b as unknown[];
    return (
      a.length === other.length && a.every((item, index) => structurallyEqual(item, other[index]))
    );
  }
  if (ArrayBuffer.isView(a)) {
    const left = new Uint8Array(a.buffer, a.byteOffset, a.byteLength);
    const view = b as ArrayBufferView;
    const right = new Uint8Array(view.buffer, view.byteOffset, view.byteLength);
    return left.length === right.length && left.every((byte, index) => byte === right[index]);
  }
  if (a instanceof Map) {
    const other = b as Map<unknown, unknown>;
    if (a.size !== other.size) return false;
    for (const [key, value] of a) {
      if (!other.has(key) || !structurallyEqual(value, other.get(key))) return false;
    }
    return true;
  }
  if (a instanceof Set) {
    const other = b as Set<unknown>;
    return a.size === other.size && [...a].every((item) => other.has(item));
  }
  if (a instanceof Date) return a.getTime() === (b as Date).getTime();
  const proto = Object.getPrototypeOf(a);
  if (proto !== Object.prototype && proto !== null) return false;
  const left = Object.keys(a);
  const right = Object.keys(b);
  return (
    left.length === right.length &&
    left.every(
      (key) =>
        Object.hasOwn(b, key) &&
        structurallyEqual((a as Record<string, unknown>)[key], (b as Record<string, unknown>)[key]),
    )
  );
}

const loading: Snapshot<never> = Object.freeze({ status: "loading", value: undefined });

/** The store {@link observe} returns. */
class ObservedStore<T> implements Observable<T> {
  readonly #read: () => Promise<T>;
  readonly #source: ChangeSource;
  readonly #equals: (a: T, b: T) => boolean;
  readonly #grace: number;
  readonly #onIdle: (() => void) | undefined;
  readonly #listeners = new Set<() => void>();
  #snapshot: Snapshot<T> = loading;
  #stop: (() => void) | undefined;
  #reading = false;
  #again = false;
  #scheduled = false;
  #idle: ReturnType<typeof setTimeout> | undefined;
  /** Whether the change source failed since the store began to follow. */
  #broken = false;

  constructor(
    read: () => Promise<T>,
    source: ChangeSource,
    options: ObserveOptions<T>,
    onIdle?: () => void,
  ) {
    this.#read = read;
    this.#source = source;
    this.#equals = options.equals ?? structurallyEqual;
    this.#grace = options.gracePeriod ?? GRACE;
    this.#onIdle = onIdle;
  }

  get = (): Snapshot<T> => this.#snapshot;

  subscribe = (listener: () => void): (() => void) => {
    this.#listeners.add(listener);
    if (this.#idle !== undefined) {
      clearTimeout(this.#idle);
      this.#idle = undefined;
    }
    if (this.#stop === undefined) {
      this.#broken = false;
      this.#stop = this.#source(this.#wake, this.#fail);
      this.#wake();
    }
    let subscribed = true;
    return () => {
      if (!subscribed) return;
      subscribed = false;
      this.#listeners.delete(listener);
      if (this.#listeners.size === 0) this.#leave();
    };
  };

  /** Starts the grace period, after which the store stops following. */
  #leave(): void {
    const stop = (): void => {
      this.#idle = undefined;
      if (this.#listeners.size > 0) return;
      this.#stop?.();
      this.#stop = undefined;
      this.#onIdle?.();
    };
    if (this.#grace <= 0) {
      stop();
      return;
    }
    this.#idle = setTimeout(stop, this.#grace);
    // A pending grace period keeps no Node.js process alive.
    (this.#idle as { unref?: () => void }).unref?.();
  }

  /**
   * The change source could not start, or ended with an error: the store shows why, and reads no
   * more until it follows again, since nothing tells it of changes.
   */
  #fail = (error: unknown): void => {
    this.#broken = true;
    this.#set(Object.freeze({ status: "failed", value: this.#snapshot.value, error }));
  };

  #set(next: Snapshot<T>): void {
    if (next === this.#snapshot) return;
    this.#snapshot = next;
    for (const listener of [...this.#listeners]) listener();
  }

  /** A change: one read more, at the end of this turn, or after the read in flight. */
  #wake = (): void => {
    if (this.#reading) {
      this.#again = true;
      return;
    }
    if (this.#scheduled) return;
    this.#scheduled = true;
    queueMicrotask(() => {
      this.#scheduled = false;
      void this.#run();
    });
  };

  async #run(): Promise<void> {
    if (this.#stop === undefined || this.#broken) return;
    this.#reading = true;
    let next: Snapshot<T>;
    try {
      const value = await this.#read();
      const before = this.#snapshot;
      const same = before.status === "ready" && this.#equals(before.value as T, value);
      next = same ? before : Object.freeze({ status: "ready", value });
    } catch (error) {
      next = notArrived(error)
        ? loading
        : Object.freeze({ status: "failed", value: this.#snapshot.value, error });
    }
    this.#reading = false;
    if (!this.#broken) this.#set(next);
    if (this.#again) {
      this.#again = false;
      this.#wake();
    }
  }
}

/**
 * Observes a read: `read` runs once the store has a subscriber, then again after each change
 * `changes` reports, and subscribers hear of each result that differs from the last. A read that
 * rejects with `unknown_stream`, or `missing` for bytes not held whole, shows as `"loading"`, so
 * that a read of something that has not arrived yet is no error.
 *
 * ```ts
 * const note = observe(
 *   async () => (await space.document(id)).text("body"),
 *   (wake) => space.onChange(wake),
 * );
 * const stop = note.subscribe(() => render(note.get()));
 * ```
 */
export function observe<T>(
  read: () => Promise<T>,
  changes: ChangeSource,
  options: ObserveOptions<T> = {},
): Observable<T> {
  return new ObservedStore(read, changes, options);
}

/** The shared stores, by owner and key, while they follow. */
const shared = new WeakMap<object, Map<string, Observable<unknown>>>();

/**
 * @internal The store under `key` for `owner` (a device), made with `read` and `changes` when there
 * is none: the same object while anyone subscribes to it, and for the grace period after.
 */
export function sharedStore<T>(
  owner: object,
  key: string,
  read: () => Promise<T>,
  changes: ChangeSource,
): Observable<T> {
  let stores = shared.get(owner);
  if (stores === undefined) {
    stores = new Map();
    shared.set(owner, stores);
  }
  const found = stores.get(key);
  if (found !== undefined) return found as Observable<T>;
  const made: Observable<T> = new ObservedStore(read, changes, {}, () => {
    if (stores.get(key) === made) stores.delete(key);
  });
  stores.set(key, made as Observable<unknown>);
  return made;
}

/** The identity of each function or validator a shared store is keyed on. */
const identities = new WeakMap<object, number>();
let nextIdentity = 1;

/** @internal A number that names `value` for as long as it lives, for keys of shared stores. */
export function identityOf(value: object | undefined): number {
  if (value === undefined) return 0;
  let id = identities.get(value);
  if (id === undefined) {
    id = nextIdentity++;
    identities.set(value, id);
  }
  return id;
}

/**
 * @internal A change source over a feed that starts asynchronously, such as `blobs.changes()`:
 * `start(wake)` resolves to the function that stops it. Stopping before it started stops it as
 * soon as it does; a start that rejects shows in the store as `"failed"`.
 */
export function asyncSource(start: (wake: () => void) => Promise<() => void>): ChangeSource {
  return (wake, fail) => {
    let stopped = false;
    let stop: (() => void) | undefined;
    start(() => {
      if (!stopped) wake();
    }).then(
      (stopFeed) => {
        if (stopped) stopFeed();
        else stop = stopFeed;
      },
      (error: unknown) => {
        if (!stopped) fail(error);
      },
    );
    return () => {
      stopped = true;
      stop?.();
    };
  };
}

/** @internal Rejects a wait that takes longer than a number of milliseconds JavaScript can hold. */
export function milliseconds(within: number): number {
  if (!Number.isFinite(within) || within < 0) {
    throw new FrasilError(
      "invalid_input",
      "A wait is a finite, non-negative number of milliseconds.",
    );
  }
  return within;
}
