/**
 * Reading a blob that need not be whole on this device: what a read does about a blob it has to
 * fetch, where a blob stands here, and a reader that gives any range of a blob as its chunks
 * arrive and open.
 *
 * @module
 */

import { FrasilError } from "./errors.js";
import { call, callAsync, Handle, type raw } from "./runtime.js";

/**
 * What a read does about a blob this device does not hold whole. A blob the device holds is read
 * from the device, whatever the read says. With none of them, the read fetches the blob and
 * leaves it in the cache, within the device's budget (`Options.blobCache`).
 */
export interface ReadOptions {
  /**
   * Keeps the blob: fetched or cached, it stays on the device until `Blobs.dropLocal`, outside
   * the cache's budget. A read that cannot fetch the blob now still marks it kept, and the device
   * fetches it by itself once it can. Not with `uncached`.
   */
  readonly keep?: boolean;
  /**
   * Stores nothing of a blob the read fetches: its chunks pass through memory, a few at a time.
   * A blob the device held before, whole or in part, stays as it was. Not with `keep`.
   */
  readonly uncached?: boolean;
  /**
   * Fetches nothing: the read gives a blob only when the device holds it whole, and never waits
   * on the network.
   */
  readonly local?: boolean;
}

/** How a reader reads: a read's options, and how far it fetches ahead. */
export interface ReaderOptions extends ReadOptions {
  /**
   * How many chunks of 1,048,536 bytes the reader fetches ahead of where it reads: 8 unless
   * given, at most 64. A reader that stores nothing holds one sealed chunk more than this in
   * memory.
   */
  readonly readAhead?: number;
}

/** How a blob stands on this device: kept until the application drops it, cached, or absent. */
export type BlobState = "kept" | "cached" | "absent";

/** Where a blob stands on this device, from `Blobs.local`. */
export interface BlobLocal {
  /**
   * `kept`: the device keeps it until `Blobs.dropLocal`; a blob this device put is kept until a
   * peer holds its bytes. `cached`: the device holds it within its cache's budget, and may drop
   * it. `absent`: the device holds nothing of it, and a read fetches it.
   */
  readonly state: BlobState;
  /** The bytes the device stores of it: its sealed chunks and header, which may be a part of it. */
  readonly bytes: number;
  /** The blob's size. */
  readonly size: number;
}

/**
 * Which checks have passed on what a reader gave. `chunks`: every byte given comes from a chunk
 * that opened under the blob's key at its own place, and the checks that need the whole blob have
 * not run, so the bytes may yet prove not to be the blob's; the reader then fails with
 * `object_mismatch`. `whole`: every check passed, and the bytes are the blob's.
 */
export type Verified = "chunks" | "whole";

/** A call that can be given up. */
export interface Abortable {
  /** Aborting it ends the call, which rejects with the signal's reason; the reader lives on. */
  readonly signal?: AbortSignal;
}

/** The most bytes one read of the module gives: a chunk's. */
const CHUNK = 1_048_536;

/** How many bytes a stream reads at a time. */
const PIECE = 262_144;

/**
 * A reader over one blob, from `Blobs.openReader`: it reads any range of the blob and fetches
 * only the chunks that hold it, from the peers and members connected, so a large file plays or
 * is searched without being downloaded. Bytes are given once their chunk arrived and opened.
 * Close it when done: an open reader keeps what it reads from being dropped, and one that stores
 * nothing holds chunks in memory.
 *
 * Its calls run one after another, in the order made. A call that is aborted, and a stream that
 * is cancelled, give up what they asked the connections for; the reader can be read again.
 */
export class BlobReader extends Handle<raw.BlobReader> {
  /** The calls made and not ended, each waiting for the one before it. */
  #tail: Promise<void> = Promise.resolve();
  /** What stops the call that runs in the module now, if one does. */
  #running: object | undefined;
  #closed = false;
  /** What {@link BlobReader.verified} and {@link BlobReader.size} said last, for a closed reader. */
  #verified: Verified = "chunks";
  #size: number | undefined;

  private constructor(value: raw.BlobReader) {
    super(value, "BlobReader");
  }

  /** @internal */
  static wrap(value: raw.BlobReader, options: ReaderOptions): BlobReader {
    const reader = new BlobReader(value);
    if (options.readAhead !== undefined) call(() => value.setReadAhead(options.readAhead ?? 0));
    return reader;
  }

  /**
   * The blob's size, once a chunk has opened under its header in this reader: `undefined` before
   * its first read or {@link BlobReader.fetchSize}. It decides what is read; the size the
   * stream's list shows is only what the blob's writer wrote there.
   */
  get size(): number | undefined {
    if (!this.isDisposed) this.#size = call(() => this.raw().size as number | undefined);
    return this.#size;
  }

  /** Which checks have passed on what the reader gave. */
  get verified(): Verified {
    if (!this.isDisposed) this.#verified = call(() => this.raw().verified as Verified);
    return this.#verified;
  }

  /**
   * How many sealed bytes the reader holds in memory, of chunks it fetched to store nothing: as
   * it stood before the call that runs now, if one does, and none once closed.
   */
  get windowBytes(): number {
    if (this.isDisposed) return 0;
    return call(() => this.raw().windowBytes);
  }

  /** Whether {@link BlobReader.close} was called. */
  get isClosed(): boolean {
    return this.#closed;
  }

  /**
   * Runs `body` once the calls made before it ended. `token` is what a stream or a signal stops
   * it by, while it is the one that runs.
   */
  async #queued<T>(
    token: object,
    signal: AbortSignal | undefined,
    body: () => Promise<T>,
  ): Promise<T> {
    const before = this.#tail;
    let done: () => void = () => {};
    this.#tail = new Promise<void>((resolve) => {
      done = resolve;
    });
    const abort = (): void => this.#stop(token);
    try {
      await before;
      signal?.throwIfAborted();
      if (this.#closed) throw closedError();
      signal?.addEventListener("abort", abort, { once: true });
      this.#running = token;
      return await callAsync(body);
    } catch (error) {
      if (signal?.aborted) throw signal.reason;
      if (this.#closed && isCancelled(error)) throw closedError();
      throw error;
    } finally {
      signal?.removeEventListener("abort", abort);
      if (this.#running === token) this.#running = undefined;
      done();
    }
  }

  /** Stops the call `token` names, if it is the one that runs in the module. */
  #stop(token: object): void {
    if (this.#running !== token || this.isDisposed) return;
    try {
      this.raw().cancel();
    } catch {
      // After a panic: the call rejects by itself.
    }
  }

  /**
   * The blob's size, once a chunk has opened under its header: fetched with the header when the
   * device does not hold them. Rejects as {@link BlobReader.read} does.
   */
  fetchSize(options: Abortable = {}): Promise<number> {
    return this.#queued({}, options.signal, () => this.raw().fetchSize() as Promise<number>);
  }

  /**
   * `length` bytes of the blob from byte `offset`, fewer at its end and none past it. The chunks
   * that hold them are fetched first when the device does not hold them, ahead of everything
   * else asked of the space's connections, with the chunks after them behind.
   *
   * Rejects with `missing` while the device does not hold a chunk and the reader is `local`, or
   * nothing is connected that could send it; `timeout` when nothing the reader asked for arrives
   * for half a minute; `decrypt` or `malformed` for a chunk that does not open. After each of
   * these the reader lives on and the read may be made again. `object_mismatch` when the blob was
   * refused: the reader has then failed for good.
   */
  read(offset: number, length: number, options: Abortable = {}): Promise<Uint8Array> {
    whole(offset, "offset");
    whole(length, "length");
    return this.#queued({}, options.signal, () => this.#read(offset, length));
  }

  async #read(offset: number, length: number): Promise<Uint8Array> {
    const first = (await this.raw().read(offset, Math.min(length, CHUNK))) as Uint8Array;
    if (first.length >= length || first.length === 0) return first;
    // More than a chunk: the module gives one at a time.
    const out = new Uint8Array(length);
    out.set(first);
    let filled = first.length;
    while (filled < length) {
      const piece = (await this.raw().read(
        offset + filled,
        Math.min(length - filled, CHUNK),
      )) as Uint8Array;
      if (piece.length === 0) break;
      out.set(piece, filled);
      filled += piece.length;
    }
    return filled === length ? out : out.slice(0, filled);
  }

  /**
   * The blob's bytes from byte `offset` (0 unless given) to its end, as a stream that reads only
   * as fast as it is read from: it holds one piece of 262,144 bytes ahead of its consumer.
   * Cancelling it gives up the read it waits for and what that asked of the connections. The
   * stream errors as {@link BlobReader.read} rejects.
   */
  stream(offset = 0): ReadableStream<Uint8Array> {
    whole(offset, "offset");
    let position = offset;
    let token: object | undefined;
    let cancelled = false;
    return new ReadableStream<Uint8Array>({
      pull: async (controller) => {
        token = {};
        let piece: Uint8Array;
        try {
          piece = await this.#queued(token, undefined, () => {
            if (cancelled) throw new FrasilError("cancelled", "the stream was cancelled");
            return this.raw().read(position, PIECE) as Promise<Uint8Array>;
          });
        } catch (error) {
          if (cancelled) return;
          throw error;
        }
        if (cancelled) return;
        if (piece.length === 0) {
          controller.close();
          return;
        }
        position += piece.length;
        controller.enqueue(piece);
      },
      cancel: () => {
        cancelled = true;
        if (token !== undefined) this.#stop(token);
      },
    });
  }

  /**
   * Ends the reader: the call that runs gives up, its fetches stop, what it held in memory is
   * freed, and the device looks at its cache, so that a blob it held for this reader alone goes.
   * It resolves once the calls made before it have ended, so that nothing of the reader uses the
   * blob then and `Blobs.dropLocal` may drop it. Calls made after it reject with `disposed`.
   * Closing twice does nothing.
   */
  async close(): Promise<void> {
    if (this.#closed) return;
    this.#closed = true;
    // The calls made before: the one that runs in the module stops, and ends the reader there
    // before it settles; the ones behind it reject without reaching the module.
    const calls = this.#tail;
    try {
      if (!this.isDisposed) {
        await callAsync(() => this.raw().close() as Promise<void>);
        await calls;
        this.#verified = call(() => this.raw().verified as Verified);
        this.#size = call(() => this.raw().size as number | undefined);
      }
    } finally {
      await calls;
      this.free();
    }
  }
}

function closedError(): FrasilError {
  return new FrasilError("disposed", "This BlobReader was closed and cannot be read any more.");
}

function isCancelled(error: unknown): boolean {
  return error instanceof FrasilError && error.code === "cancelled";
}

function whole(value: number, what: string): void {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new FrasilError("invalid_input", `${what} must be a whole number of bytes.`);
  }
}
