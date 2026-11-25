/**
 * The one error class every operation throws or rejects with.
 *
 * @module
 */

/**
 * The codes the package uses.
 *
 * - A check of the specification failed: the class in snake case, as the wire writes it
 *   (`malformed`, `bad_signature`, `not_a_member`, …), with the class's own name in
 *   {@link FrasilError.class} (`Malformed`).
 * - The client's own failures: `store` (the store failed), `conflict` (another tab of this device
 *   committed first), `no_randomness` (the platform has no working `crypto.getRandomValues`),
 *   `unknown_space`, `unknown_stream`, `not_allowed` (the device may not act so in the space;
 *   nothing was signed), `sync_before_writing` (the store was restored: sync the space before
 *   writing there), `rotation_due` (the space must rotate first), `adapter` (the adapter refused
 *   the change), `connection` (a connection failed), `timeout`, `delayed` (a deposit in a device
 *   mailbox, such as a welcome, was kept to be sent again by itself), `limit_passed` (a comparison's time
 *   limit passed under `stopAtLimit`; nothing was written), `unsupported` (not in this build),
 *   `released` (the stream is released), `invalid_input` (an argument that does not read).
 * - Another protocol revision: `incompatible_data` (this device's store, or a space
 *   file, was written by another revision; nothing of it was read or changed: delete the store and
 *   make a new device, which gets everything shared back by sync), `other_revision` (the peer or
 *   member at the other end runs another revision; update one of them). {@link isOtherRevision}
 *   tells both. `needs_later_version` (the space uses a document of a later version than this
 *   build: nothing was signed, and nothing more is signed there; update the app).
 * - Why this device may not write in a space now (ext-guests.md, "The writer's decision"): `left`
 *   (it asked to leave), `session_ended` (its guest session is over), `window_elapsed` (it has
 *   not heard from another member within the space's bounded window), `not_online` (it has not
 *   synced with a peer recently enough). The change was not made; it can still read.
 * - This package: `disposed` (an object used after `free()`), `panicked` (the WebAssembly module
 *   stopped; reload), `unknown` (a failure this version of the package cannot name).
 */
export type KnownErrorCode =
  | "store"
  | "conflict"
  | "no_randomness"
  | "unknown_space"
  | "unknown_stream"
  | "not_allowed"
  | "sync_before_writing"
  | "rotation_due"
  | "adapter"
  | "connection"
  | "timeout"
  | "delayed"
  | "limit_passed"
  | "unsupported"
  | "invalid_input"
  | "released"
  | "incompatible_data"
  | "other_revision"
  | "needs_later_version"
  | "left"
  | "session_ended"
  | "window_elapsed"
  | "not_online"
  | "disposed"
  | "panicked"
  | "unknown";

/** Every code: the known ones, and a specification class in snake case. */
export type ErrorCode = KnownErrorCode | (string & {});

/** What to do about the package's own failures, which the module does not raise. */
const advice: Partial<Record<KnownErrorCode, string>> = {
  store:
    "check that the browser allows this origin storage and has space, then open the device again",
  disposed: "keep the object until you are done with it, or get it again",
  panicked: "reload the page; report the panic message if it happens again",
  invalid_input: "pass a value of the form the message names",
  unknown: "update the package, or report the failure",
};

/** What every operation throws or rejects with. */
export class FrasilError extends Error {
  override readonly name = "FrasilError";
  /** What failed; see {@link KnownErrorCode}. */
  readonly code: ErrorCode;
  /** For a failed check of the specification, its class as the specification names it. */
  readonly class?: string;
  /** What to do about it, in a sentence an application can show or log. */
  readonly whatToDo: string;

  constructor(
    code: ErrorCode,
    message: string,
    fields: { class?: string; whatToDo?: string; cause?: unknown } = {},
  ) {
    super(message, fields.cause === undefined ? undefined : { cause: fields.cause });
    this.code = code;
    if (fields.class !== undefined) this.class = fields.class;
    this.whatToDo =
      fields.whatToDo ?? advice[code as KnownErrorCode] ?? "report the failure if it persists";
  }
}

/**
 * Whether an error means this device met data or a party of another protocol revision:
 * `incompatible_data` (start the device over) or `other_revision` (update the app or the peer).
 */
export function isOtherRevision(error: unknown): boolean {
  return (
    error instanceof FrasilError &&
    (error.code === "incompatible_data" || error.code === "other_revision")
  );
}
