/**
 * Where a device keeps its records (at-rest.md, "What the application provides"): a
 * {@link Storage}, which names a {@link Store}: one in memory, one in IndexedDB, or the
 * application's own. No store decides anything. The library seals every record, chooses every
 * address, and decides what to write; a store only reads, scans in address order, and compares
 * and writes atomically. Beside the records it keeps the device's sealed keys, which open only
 * with the unlock key.
 *
 * Addresses and records are opaque bytes. Nothing in them opens without the unlocked device, and a
 * record anyone else wrote into the store is refused when read.
 *
 * @module
 */

import { FrasilError } from "./errors.js";

/** One commit: if every expectation holds, delete then put, atomically and durably. */
export interface Commit {
  /** Addresses and what each must hold: the record, or `null` for nothing. */
  readonly expect: readonly (readonly [Uint8Array, Uint8Array | null])[];
  /** Records to write, by address. */
  readonly puts: readonly (readonly [Uint8Array, Uint8Array])[];
  /** Addresses to delete. */
  readonly deletes: readonly Uint8Array[];
}

/**
 * What a device's store does. Each method may answer at once or with a promise. A store that
 * throws or rejects makes the operation fail with code `store`.
 */
export interface Store {
  /** The record at `address`, or `undefined`. */
  get(address: Uint8Array): Promise<Uint8Array | undefined> | Uint8Array | undefined;
  /** Every `[address, record]` whose address starts with `prefix`, in bytewise address order. */
  scan(prefix: Uint8Array): Promise<[Uint8Array, Uint8Array][]> | [Uint8Array, Uint8Array][];
  /**
   * If every expectation holds, deletes then puts in one atomic, durable step and answers `true`;
   * otherwise changes nothing and answers `false`.
   *
   * A store with no room for the puts rejects with an error named `QuotaExceededError`, as the
   * browser's own is, or with one whose `cause` is such an error, having written nothing. The
   * device then drops blobs from its cache and commits again.
   */
  commit(commit: Commit): Promise<boolean> | boolean;
  /** The device's sealed keys, kept beside the records; `undefined` before the device is made. */
  loadSealedKeys(): Promise<Uint8Array | undefined> | Uint8Array | undefined;
  /** Keeps the device's sealed keys beside the records, durably, replacing any. */
  saveSealedKeys(sealed: Uint8Array): Promise<void> | void;
}

function hexOf(bytes: Uint8Array): string {
  let text = "";
  for (const byte of bytes) text += byte.toString(16).padStart(2, "0");
  return text;
}

function same(a: Uint8Array | undefined | null, b: Uint8Array | undefined | null): boolean {
  if (!a || !b) return !a && !b;
  if (a.length !== b.length) return false;
  for (let index = 0; index < a.length; index += 1) if (a[index] !== b[index]) return false;
  return true;
}

function startsWith(address: Uint8Array, prefix: Uint8Array): boolean {
  if (address.length < prefix.length) return false;
  for (let index = 0; index < prefix.length; index += 1) {
    if (address[index] !== prefix[index]) return false;
  }
  return true;
}

function compare(a: Uint8Array, b: Uint8Array): number {
  const length = Math.min(a.length, b.length);
  for (let index = 0; index < length; index += 1) {
    const difference = (a[index] ?? 0) - (b[index] ?? 0);
    if (difference !== 0) return difference;
  }
  return a.length - b.length;
}

/**
 * A {@link Store} in memory: records last as long as this object. For tests, and for a device that
 * keeps nothing past the page.
 */
export class MemoryStore implements Store {
  readonly #records = new Map<string, [Uint8Array, Uint8Array]>();
  #sealedKeys: Uint8Array | undefined;

  loadSealedKeys(): Uint8Array | undefined {
    return this.#sealedKeys && new Uint8Array(this.#sealedKeys);
  }

  saveSealedKeys(sealed: Uint8Array): void {
    this.#sealedKeys = new Uint8Array(sealed);
  }

  get(address: Uint8Array): Uint8Array | undefined {
    const record = this.#records.get(hexOf(address))?.[1];
    return record && new Uint8Array(record);
  }

  scan(prefix: Uint8Array): [Uint8Array, Uint8Array][] {
    return [...this.#records.values()]
      .filter(([address]) => startsWith(address, prefix))
      .sort(([a], [b]) => compare(a, b))
      .map(([address, record]) => [new Uint8Array(address), new Uint8Array(record)]);
  }

  commit(commit: Commit): boolean {
    const holds = commit.expect.every(([address, record]) =>
      same(this.#records.get(hexOf(address))?.[1], record),
    );
    if (!holds) return false;
    for (const address of commit.deletes) this.#records.delete(hexOf(address));
    for (const [address, record] of commit.puts) {
      this.#records.set(hexOf(address), [new Uint8Array(address), new Uint8Array(record)]);
    }
    return true;
  }

  /** How many records it holds. */
  get size(): number {
    return this.#records.size;
  }
}

/** The object store of the database: binary addresses to records. */
const RECORDS = "records";

/** The object store of the device's sealed keys, under {@link SEALED}. */
const KEYS = "keys";
const SEALED = "device";

function storeError(what: string, cause: unknown): FrasilError {
  const detail = cause instanceof Error || cause instanceof DOMException ? ` ${cause.message}` : "";
  // The cause stays on the error: a write the browser refused past the origin's quota is told
  // from other failures by its name, `QuotaExceededError`.
  return new FrasilError("store", `The store could not ${what}.${detail}`, { cause });
}

/** A request's result, as a promise. */
function done<T>(request: IDBRequest<T>, what: string): Promise<T> {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(storeError(what, request.error));
  });
}

/** The first address after every address that starts with `prefix`, if there is one. */
function after(prefix: Uint8Array): Uint8Array | undefined {
  const end = Array.from(prefix);
  while (end.length > 0) {
    const last = end.pop() ?? 0xff;
    if (last < 0xff) {
      end.push(last + 1);
      return new Uint8Array(end);
    }
  }
  return undefined;
}

/** An address as an IndexedDB key: a binary key, in a buffer of its own. */
function keyOf(address: Uint8Array): ArrayBuffer {
  return address.slice().buffer;
}

function bytesOf(value: unknown): Uint8Array {
  if (value instanceof Uint8Array) return new Uint8Array(value);
  if (value instanceof ArrayBuffer) return new Uint8Array(value.slice(0));
  if (ArrayBuffer.isView(value)) {
    return new Uint8Array(
      value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength),
    );
  }
  throw storeError("read a record: it holds something other than bytes", undefined);
}

/**
 * A {@link Store} in IndexedDB. Addresses are binary keys, which IndexedDB orders bytewise, as a
 * scan must. Each commit is one `readwrite` transaction, which the browser serialises across the
 * tabs of the origin, so two tabs of one device never both advance its head from the same state.
 * The sealed device keys are in a second object store.
 *
 * ```ts
 * const store = await IndexedDbStore.open("my-app-frasil");
 * const device = await Device.open(Storage.of(store), unlockKey);
 * ```
 */
export class IndexedDbStore implements Store {
  readonly #db: IDBDatabase;
  readonly #keyRange: typeof IDBKeyRange;

  private constructor(db: IDBDatabase, keyRange: typeof IDBKeyRange) {
    this.#db = db;
    this.#keyRange = keyRange;
    db.onversionchange = () => db.close();
  }

  /**
   * Opens (or creates) the database `name`.
   *
   * @throws {@link FrasilError} `store` if IndexedDB is unavailable or refuses.
   */
  static async open(
    name = "frasil",
    indexedDB: IDBFactory | undefined = globalThis.indexedDB,
    keyRange: typeof IDBKeyRange | undefined = globalThis.IDBKeyRange,
  ): Promise<IndexedDbStore> {
    if (!indexedDB || !keyRange) {
      throw storeError("open: IndexedDB is not available here", undefined);
    }
    let request: IDBOpenDBRequest;
    try {
      request = indexedDB.open(name, 2);
    } catch (error) {
      throw storeError("open", error);
    }
    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains(RECORDS)) db.createObjectStore(RECORDS);
      if (!db.objectStoreNames.contains(KEYS)) db.createObjectStore(KEYS);
    };
    return new IndexedDbStore(await done(request, "open"), keyRange);
  }

  /** Deletes the database `name` and every record in it. Close every store opened on it first. */
  static async deleteDatabase(
    name = "frasil",
    indexedDB: IDBFactory | undefined = globalThis.indexedDB,
  ): Promise<void> {
    if (!indexedDB) return;
    await done(indexedDB.deleteDatabase(name), "delete its database");
  }

  /** Runs `body` in one transaction of the object store `of`; resolves once it commits. */
  #transaction<T>(
    mode: IDBTransactionMode,
    what: string,
    body: (records: IDBObjectStore, finish: (value: T) => void) => void,
    of = RECORDS,
  ): Promise<T> {
    return new Promise((resolve, reject) => {
      let transaction: IDBTransaction;
      try {
        transaction = this.#db.transaction(of, mode, { durability: "strict" });
      } catch (error) {
        reject(storeError(what, error));
        return;
      }
      let value: T;
      transaction.oncomplete = () => resolve(value);
      transaction.onabort = () => reject(storeError(what, transaction.error));
      try {
        body(transaction.objectStore(of), (result) => {
          value = result;
        });
      } catch (error) {
        transaction.abort();
        reject(storeError(what, error));
      }
    });
  }

  get(address: Uint8Array): Promise<Uint8Array | undefined> {
    return this.#transaction("readonly", "read a record", (records, finish) => {
      const request = records.get(keyOf(address));
      request.onsuccess = () => {
        finish(request.result === undefined ? undefined : bytesOf(request.result));
      };
    });
  }

  scan(prefix: Uint8Array): Promise<[Uint8Array, Uint8Array][]> {
    const end = after(prefix);
    const range =
      prefix.length === 0
        ? undefined
        : end
          ? this.#keyRange.bound(keyOf(prefix), keyOf(end), false, true)
          : this.#keyRange.lowerBound(keyOf(prefix));
    return this.#transaction("readonly", "scan its records", (records, finish) => {
      const keys = records.getAllKeys(range);
      const values = records.getAll(range);
      values.onsuccess = () => {
        // Both requests list the range in key order, and the second completes after the first.
        const found: [Uint8Array, Uint8Array][] = keys.result.map((key, index) => [
          bytesOf(key),
          bytesOf(values.result[index]),
        ]);
        finish(found);
      };
    });
  }

  commit(commit: Commit): Promise<boolean> {
    return this.#transaction("readwrite", "commit", (records, finish) => {
      let pending = commit.expect.length;
      let holds = true;
      const write = () => {
        if (!holds) {
          finish(false);
          return;
        }
        for (const address of commit.deletes) records.delete(keyOf(address));
        for (const [address, record] of commit.puts) records.put(record.slice(), keyOf(address));
        finish(true);
      };
      if (pending === 0) {
        write();
        return;
      }
      for (const [address, record] of commit.expect) {
        const request = records.get(keyOf(address));
        request.onsuccess = () => {
          const held = request.result === undefined ? undefined : bytesOf(request.result);
          if (!same(held, record)) holds = false;
          pending -= 1;
          if (pending === 0) write();
        };
      }
    });
  }

  loadSealedKeys(): Promise<Uint8Array | undefined> {
    return this.#transaction(
      "readonly",
      "read the device's keys",
      (keys, finish) => {
        const request = keys.get(SEALED);
        request.onsuccess = () => {
          finish(request.result === undefined ? undefined : bytesOf(request.result));
        };
      },
      KEYS,
    );
  }

  saveSealedKeys(sealed: Uint8Array): Promise<void> {
    return this.#transaction(
      "readwrite",
      "keep the device's keys",
      (keys, finish) => {
        keys.put(sealed.slice(), SEALED);
        finish(undefined);
      },
      KEYS,
    );
  }

  /** Closes the database connection. The store cannot be used afterwards. */
  close(): void {
    this.#db.close();
  }
}

/**
 * Where a device keeps its records: in memory, in an IndexedDB database of its own, or in a
 * {@link Store} the application supplies. {@link Device.open} opens it.
 *
 * ```ts
 * const device = await Device.open(Storage.indexedDb("my-app"), unlockKey);
 * ```
 */
export class Storage {
  readonly #open: () => Promise<Store>;

  private constructor(open: () => Promise<Store>) {
    this.#open = open;
  }

  /** In memory: everything is lost with the page. For tests and devices that keep nothing. */
  static memory(): Storage {
    return new Storage(async () => new MemoryStore());
  }

  /**
   * An IndexedDB database of the device's own, `name`, made if missing. Each commit is one
   * `readwrite` transaction, so two tabs of one device never both advance it.
   */
  static indexedDb(name: string): Storage {
    return new Storage(() => IndexedDbStore.open(name));
  }

  /** A store the application supplies, such as an {@link IndexedDbStore} it opened itself. */
  static of(store: Store): Storage {
    return new Storage(async () => store);
  }

  /** @internal The store, opened. */
  static open(storage: Storage): Promise<Store> {
    return storage.#open();
  }
}
