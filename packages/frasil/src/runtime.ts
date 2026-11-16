/**
 * Internal: loads the WebAssembly module, turns what it throws into {@link FrasilError}s, stops
 * every call after a panic, and gives every handle its `free()` and `Symbol.dispose`.
 *
 * The module is loaded once, when the package is first imported (top-level `await`), from where
 * `engine.ts` says: a file next to the package, by default.
 *
 * @internal
 * @module
 */

import { engine } from "./engine.js";
import { FrasilError } from "./errors.js";
import init, * as raw from "./wasm/frasil_wasm.js";

await init({ module_or_path: await engine });

export { raw };

// ---- Panics ---------------------------------------------------------------------------------

/** The panic message, once the module has panicked. */
let failure: string | undefined;
let rejectInFlight: (error: FrasilError) => void = () => {};
const panicked = new Promise<never>((_, reject) => {
  rejectInFlight = reject;
});
// Nobody may be waiting when it rejects.
panicked.catch(() => {});

function panicError(): FrasilError {
  return new FrasilError(
    "panicked",
    `The Frasil module stopped after an internal error and must be reloaded. ${failure ?? ""}`.trim(),
  );
}

raw.onPanic((message: string) => {
  failure = message;
  rejectInFlight(panicError());
});

/** The panic message if the module has panicked, for diagnostics; `undefined` otherwise. */
export function panicMessage(): string | undefined {
  return failure;
}

// ---- Errors ---------------------------------------------------------------------------------

/** What the binding or the module threw, as the error the application sees. */
export function toFrasilError(thrown: unknown): unknown {
  if (thrown instanceof FrasilError) return thrown;
  if (failure !== undefined || thrown instanceof WebAssembly.RuntimeError) return panicError();
  if (thrown instanceof Error && thrown.name === "FrasilError") {
    const {
      code,
      class: name,
      whatToDo,
    } = thrown as Error & {
      code?: unknown;
      class?: unknown;
      whatToDo?: unknown;
    };
    return new FrasilError(typeof code === "string" ? code : "unknown", thrown.message, {
      ...(typeof name === "string" ? { class: name } : {}),
      ...(typeof whatToDo === "string" ? { whatToDo } : {}),
    });
  }
  return thrown;
}

function refuseAfterPanic(): void {
  if (failure !== undefined) throw panicError();
}

/** Runs a synchronous call into the module. */
export function call<T>(body: () => T): T {
  refuseAfterPanic();
  try {
    return body();
  } catch (thrown) {
    throw toFrasilError(thrown);
  }
}

/**
 * Runs an asynchronous call into the module. If the module panics while it is in flight, its
 * promise would never settle; this one rejects with `panicked` instead.
 */
export async function callAsync<T>(body: () => Promise<T>): Promise<T> {
  refuseAfterPanic();
  try {
    return await Promise.race([body(), panicked]);
  } catch (thrown) {
    throw toFrasilError(thrown);
  }
}

/**
 * Calls `callback` with each item `source.next()` resolves to, until it resolves `undefined`, it
 * rejects (`onError` gets the error), or the returned function is called. The source is freed
 * then.
 */
export function follow<T>(
  source: Freeable & { next(): Promise<unknown> },
  callback: (item: T) => void,
  onError?: (error: unknown) => void,
): () => void {
  let stopped = false;
  const stop = (): void => {
    if (stopped) return;
    stopped = true;
    try {
      source.free();
    } catch {
      // Freed already, or after a panic.
    }
  };
  void (async () => {
    for (;;) {
      let item: T | undefined;
      try {
        item = await callAsync(() => source.next() as Promise<T | undefined>);
      } catch (error) {
        if (!stopped) onError?.(error);
        break;
      }
      if (stopped || item === undefined) break;
      callback(item);
    }
    stop();
  })();
  return stop;
}

// ---- Handles --------------------------------------------------------------------------------

/** What every generated class has. */
interface Freeable {
  free(): void;
}

/**
 * The `Symbol.dispose` of this runtime, or the well-known fallback where the runtime has none yet,
 * which is what TypeScript's own `using` lowering looks up.
 */
export const disposeSymbol: typeof Symbol.dispose =
  (Symbol as { dispose?: typeof Symbol.dispose }).dispose ??
  (Symbol.for("Symbol.dispose") as typeof Symbol.dispose);

/**
 * A JavaScript object that owns a value in WebAssembly memory. Call `free()`, or declare it with
 * `using`, when you are done; every later use throws a {@link FrasilError} with code `disposed`.
 */
export abstract class Handle<Raw extends Freeable> {
  #raw: Raw | undefined;
  #name: string;

  /** @internal */
  protected constructor(value: Raw, name: string) {
    this.#raw = value;
    this.#name = name;
  }

  /** @internal The raw object, or `disposed`. */
  static rawOf<R extends Freeable>(handle: Handle<R>): R {
    const value = handle.#raw;
    if (value === undefined) {
      throw new FrasilError(
        "disposed",
        `This ${handle.#name} was freed and cannot be used any more.`,
      );
    }
    return value;
  }

  /** @internal The raw object, or `disposed`. */
  protected raw(): Raw {
    return Handle.rawOf(this);
  }

  /** Whether this object was freed, so that it can no longer be used. */
  get isDisposed(): boolean {
    return this.#raw === undefined;
  }

  /** Releases the value in WebAssembly memory. Idempotent. Later uses throw `disposed`. */
  free(): void {
    const value = this.#raw;
    this.#raw = undefined;
    if (value === undefined) return;
    try {
      value.free();
    } catch {
      // Only possible after a panic, when the module may trap again; the object is gone either
      // way, and the error that matters was reported when the panic happened.
    }
  }

  /** Frees it: `using device = await Device.open(…)`. */
  [disposeSymbol](): void {
    this.free();
  }
}
