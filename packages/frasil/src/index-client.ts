/**
 * A page's view of an index that a dedicated worker keeps (`@frasil/client/index`): queries and
 * live queries, sent over a port to the worker's `serveIndex`. It loads no WebAssembly.
 *
 * @module
 */

import { FrasilError } from "./errors.js";
import { type Observable, type Snapshot, structurallyEqual } from "./observe.js";

/** Where messages go and come from: a worker, or a `MessagePort`. */
interface Port {
  postMessage(message: unknown): void;
  addEventListener(type: "message" | "error", listener: (event: Event) => void): void;
  removeEventListener(type: "message" | "error", listener: (event: Event) => void): void;
}

type Answer =
  | { frasilIndex: number; rows: unknown[] }
  | { frasilIndex: number; error: { code: string; message: string } };

/** A query's parameter: `null`, a boolean, a number, a `bigint`, a string or bytes. */
type Param = null | undefined | boolean | number | bigint | string | Uint8Array;

/**
 * The index a worker serves with `serveIndex`, from a page.
 *
 * ```ts
 * const index = new IndexClient(worker);
 * const rows = await index.query("SELECT count(*) AS n FROM task");
 * const open = index.watch("SELECT title FROM task WHERE done = 0");
 * ```
 */
export class IndexClient {
  readonly #port: Port;
  readonly #waiting = new Map<number, (answer: Answer) => void>();
  #next = 1;
  #closed: { code: string; message: string } | undefined;

  constructor(port: Port) {
    this.#port = port;
    port.addEventListener("message", (event: Event) => {
      const answer = (event as MessageEvent).data as Answer | undefined;
      if (typeof answer !== "object" || answer === null || !("frasilIndex" in answer)) return;
      this.#waiting.get(answer.frasilIndex)?.(answer);
    });
    // A worker that fails ends every query and live query in flight.
    port.addEventListener("error", (event: Event) => {
      const message = (event as ErrorEvent).message || "the index's worker failed";
      this.close(message);
    });
  }

  /**
   * Stops using the worker, as when the page terminates it: every query and live query in flight
   * rejects or fails with `closed`, and so does every later one.
   */
  close(message = "the index client is closed"): void {
    if (this.#closed !== undefined) return;
    this.#closed = { code: "closed", message };
    const waiting = [...this.#waiting.entries()];
    this.#waiting.clear();
    for (const [id, answer] of waiting) answer({ frasilIndex: id, error: this.#closed });
  }

  /** Runs a read-only query in the worker: its rows. */
  query<R = { readonly [column: string]: unknown }>(
    sql: string,
    params: readonly Param[] = [],
  ): Promise<R[]> {
    if (this.#closed !== undefined) {
      return Promise.reject(new FrasilError(this.#closed.code, this.#closed.message));
    }
    const id = this.#next++;
    return new Promise((resolve, reject) => {
      this.#waiting.set(id, (answer) => {
        this.#waiting.delete(id);
        if ("error" in answer) reject(new FrasilError(answer.error.code, answer.error.message));
        else resolve(answer.rows as R[]);
      });
      this.#port.postMessage({ frasilIndex: id, op: "query", sql, params: [...params] });
    });
  }

  /**
   * A live query in the worker, as a store: it starts once subscribed and stops when the last
   * subscriber leaves; subscribers hear of its rows when they differ.
   */
  watch<R = { readonly [column: string]: unknown }>(
    sql: string,
    params: readonly Param[] = [],
  ): Observable<R[]> {
    const listeners = new Set<() => void>();
    let snapshot: Snapshot<R[]> = Object.freeze({ status: "loading", value: undefined });
    let id: number | undefined;
    const set = (next: Snapshot<R[]>): void => {
      snapshot = next;
      for (const listener of [...listeners]) listener();
    };
    return {
      get: () => snapshot,
      subscribe: (listener) => {
        listeners.add(listener);
        const closed = this.#closed;
        if (closed !== undefined) {
          if (snapshot.status !== "failed") {
            set(
              Object.freeze({
                status: "failed",
                value: snapshot.value,
                error: new FrasilError(closed.code, closed.message),
              }),
            );
          }
        } else if (id === undefined) {
          const watch = this.#next++;
          id = watch;
          this.#waiting.set(watch, (answer) => {
            if ("error" in answer) {
              set(
                Object.freeze({
                  status: "failed",
                  value: snapshot.value,
                  error: new FrasilError(answer.error.code, answer.error.message),
                }),
              );
            } else if (
              !(snapshot.status === "ready" && structurallyEqual(snapshot.value, answer.rows))
            ) {
              set(Object.freeze({ status: "ready", value: answer.rows as R[] }));
            }
          });
          this.#port.postMessage({ frasilIndex: watch, op: "watch", sql, params: [...params] });
        }
        let subscribed = true;
        return () => {
          if (!subscribed) return;
          subscribed = false;
          listeners.delete(listener);
          if (listeners.size === 0 && id !== undefined) {
            this.#waiting.delete(id);
            this.#port.postMessage({ frasilIndex: id, op: "unwatch" });
            id = undefined;
          }
        };
      },
    };
  }
}
