/**
 * A space, as an application sees it: its members and its streams.
 *
 * @module
 */

import type {
  Confirm,
  Device,
  HistoryMode,
  MemberId,
  PersonId,
  SpaceFileInvitation,
} from "./device.js";
import { milliseconds, type Observable, observe } from "./observe.js";
import { call, callAsync, follow, Handle, type raw } from "./runtime.js";
import {
  Blobs,
  LoroDocument,
  type Origin,
  Records,
  type StreamId,
  type Version,
  type VersionId,
} from "./streams.js";

/** A space's ID: the ID of its genesis event, as 64 hex digits. */
export type SpaceId = string;

/** A change of one space, as {@link Space.onChange} reports it. */
export interface SpaceChange {
  /** The streams whose content changed. A feed that fell behind lists every stream. */
  readonly streams: StreamId[];
  /** Whether its members or their levels may have changed. */
  readonly members: boolean;
  /**
   * Whether it holds events that are no stream's content: keys, such as a rotation or a delivery,
   * which can make changes that arrived earlier readable in any stream, or the space's own stream.
   * Read again what the device shows of the space. A feed that fell behind sets it.
   */
  readonly spaceEvents: boolean;
  /** Where it was made; a change holding several authors' events, or a feed that fell behind, is `"remote"`. */
  readonly origin: Origin;
}

/** What a member may do in a space (roster.md). */
export type Level = "read" | "write" | "administer";

/** What kind of member a space names. */
export type MemberKind = "device" | "person" | "space";

/** A member of a space. */
export interface Member {
  readonly id: MemberId;
  readonly kind: MemberKind;
  readonly level: Level;
  /** The name it was admitted with, if any: shown, never checked. */
  readonly name?: string;
  /** Its rank, 0 to 255, while it administers: a larger rank outranks a smaller one. */
  readonly rank?: number;
  /** Whether it administers marked dormant, as a recovery member is: no checkpoint waits for it. */
  readonly dormant: boolean;
}

/**
 * A checkpoint's ID, as 64 hex digits: the ID of the roster event that is the checkpoint, or of a
 * device-list event that checkpoints the list.
 */
export type CheckpointId = string;

/** A valid checkpoint that waits for votes. */
export interface PendingCheckpoint {
  readonly id: CheckpointId;
  /** Its epoch: 1 for the space's first checkpoint. */
  readonly epoch: number;
  /** The administrator that proposed it. */
  readonly proposedBy: MemberId;
  /**
   * The administrators it waits for: each must write anything after it. One that will not return
   * can be removed by another administrator, which excuses it.
   */
  readonly waitingFor: MemberId[];
}

/**
 * A checkpoint whose proposer a removal made at the same time removes: an administrator should
 * check that it is not a removed device's attempt to keep the space.
 */
export interface BackdatedCheckpoint {
  readonly checkpoint: CheckpointId;
  /** The administrator that proposed it. */
  readonly proposedBy: MemberId;
  /** The roster event that removes that administrator, as 64 hex digits. */
  readonly removal: string;
}

/** A space's checkpoints, as this device holds them ({@link Space.checkpoints}). */
export interface CheckpointStatus {
  /** The last checkpoint in effect; `null` with none. */
  readonly inEffect: CheckpointId | null;
  /** Its epoch; 0 with none. */
  readonly epoch: number;
  /** The checkpoints waiting for votes, each with whom it waits for. */
  readonly pending: PendingCheckpoint[];
  /** The checkpoint this device follows: the one in effect, or a pending one; `null` with none. */
  readonly following: CheckpointId | null;
  /** Checkpoints that are void (`BadCheckpoint`): they never take effect. */
  readonly bad: CheckpointId[];
  /** Events void as `Late`: made at the same time as the checkpoint in effect, as 64 hex digits. */
  readonly late: string[];
  /** Events void as `MixedCut`, as 64 hex digits. */
  readonly mixed: string[];
  /** Valid roster events since the last checkpoint in effect. */
  readonly rosterEventsSince: number;
  /** Bytes of frame events since the last checkpoint in effect. */
  readonly frameBytesSince: number;
  /** Whether this device forgot what came before the checkpoint in effect. */
  readonly forgot: boolean;
  /** Pending checkpoints whose record this device found wrong: it never votes for them. */
  readonly refused: CheckpointId[];
  /**
   * Pending checkpoints whose record this device cannot check yet: it waits for what the record
   * reads, and votes once it has checked it.
   */
  readonly checking: CheckpointId[];
  /**
   * Checkpoints that drop this device as an administrator while its own view says it still is one:
   * it writes nothing that builds on them.
   */
  readonly withheld: CheckpointId[];
  /**
   * Checkpoints that rival the one this device kept when it forgot: until it has fetched their
   * past, every change of the space waits.
   */
  readonly rivals: CheckpointId[];
  /** Checkpoints whose proposer a removal made at the same time removes. */
  readonly backdated: BackdatedCheckpoint[];
}

/** What a late membership change did: admitted, changed or removed a member, or something else. */
export type LateChangeKind = "grant" | "change" | "remove" | "other";

/**
 * A membership change of this device that a checkpoint made late, and that the device does not
 * make again by itself: the administrator decides whether to make it again.
 */
export interface LateChange {
  /** The late roster event, as 64 hex digits. */
  readonly event: string;
  /** The member it named; `null` for none. */
  readonly member: MemberId | null;
  readonly kind: LateChangeKind;
  /** The level it set; `null` for none. */
  readonly level: Level | null;
}

/**
 * What kind of stream a stream is: `document`, `records`, `blobs`, or another adapter's type.
 */
export type StreamKind = "document" | "records" | "blobs" | (string & {});

/** A stream of a space. */
export interface StreamInfo {
  readonly id: StreamId;
  readonly kind: StreamKind;
}

/** How much history a space file carries: everything, or from a snapshot at the exporter's heads. */
export type SpaceFileHistory = "full" | "from-snapshot";

/**
 * One part of a space file's way in: `keys`, the rotation secrets, so that whoever holds the file
 * reads the space as this device could at export; or a fresh invite the exporting device grants,
 * which admits one claimant at `level` (`read` or `write`) with nobody online, open for `lifetime`
 * seconds, 15 minutes to 7 days.
 */
export type SpaceFileWayIn = "keys" | { level: Exclude<Level, "administer">; lifetime: number };

/** An application's section of a space file: opaque bytes under its kind string. */
export interface SpaceFileSection {
  readonly kind: string;
  readonly name: string;
  readonly bytes: Uint8Array;
}

/** What {@link Space.exportSpaceFile} writes; each field has a default. */
export interface SpaceFileExport {
  /** `full` (the default), or `from-snapshot`. */
  readonly history?: SpaceFileHistory;
  /** The streams whose units the file holds; every stream when absent. */
  readonly streams?: StreamId[];
  /**
   * Which objects to embed: `all`, `none` (fetched later, from members or a peer), or every blob
   * whose stored bytes fit within this many bytes in all, 32 MiB by default.
   */
  readonly objects?: "all" | "none" | number;
  /** The way in; `["keys"]` by default. */
  readonly wayIn?: SpaceFileWayIn[];
  /**
   * The 32-byte file key the way in is sealed under; the clear when absent. How the application
   * derives it, from a passphrase through a memory-hard derivation or from a keychain item, is its
   * own; a key kept beside the file protects nothing.
   */
  readonly seal?: Uint8Array;
  /** The application's sections, for what is not in the space. */
  readonly sections?: SpaceFileSection[];
}

/** What {@link Device.sniffSpaceFile} reads of a file, with no event read and nothing opened. */
export interface SpaceFileInfo {
  readonly space: SpaceId;
  readonly kind: string;
  /** How many heads the exporter had. */
  readonly heads: number;
  /** The streams the file holds units of; absent for every stream. */
  readonly streams?: StreamId[];
  readonly history: SpaceFileHistory;
  /** How many objects the file embeds. */
  readonly objects: number;
  /** The exporting device's ID. */
  readonly exporter: MemberId;
  /** The exporter's wall clock, as seconds since the epoch, if it was known. */
  readonly time?: number;
  /** Whether the file carries a way in, and whether it is sealed under a file key. */
  readonly wayIn: "none" | "clear" | "sealed";
}

/**
 * How a file was imported: this device was a member already (`member`), it held the space by
 * keys alone already (`rereading`), the file's invite admits it on the person's consent
 * (`invited`), or the file's keys let it read (`reading`).
 */
export type SpaceFileRoad = "member" | "rereading" | "invited" | "reading";

/** What {@link Device.importSpaceFile} resolves to: the space, or an invitation to it. */
export type ImportedSpaceFile =
  | {
      readonly road: "member" | "rereading" | "reading";
      readonly space: Space;
      readonly invitation?: undefined;
    }
  | {
      readonly road: "invited";
      readonly invitation: SpaceFileInvitation;
      readonly space?: undefined;
    };

/** A space this device holds. */
export class Space extends Handle<raw.Space> {
  /** The device the space is held by. */
  readonly device: Device;
  readonly #id: SpaceId;

  private constructor(value: raw.Space, device: Device) {
    super(value, "Space");
    this.device = device;
    this.#id = value.id;
  }

  /** @internal */
  static wrap(value: raw.Space, device: Device): Space {
    return new Space(value, device);
  }

  #raw(): raw.Space {
    return this.raw();
  }

  /** The space's ID. */
  get id(): SpaceId {
    return this.#id;
  }

  /**
   * A 32-byte key for the application's own data of this space on this device, as
   * {@link Device.deriveKey} gives, under the space's own key: once the device forgets the space, no
   * call gives it again. Rejects with `invalid` for an empty purpose.
   */
  deriveKey(purpose: string): Promise<Uint8Array> {
    return callAsync(() => this.#raw().deriveKey(purpose) as Promise<Uint8Array>);
  }

  /** The kind of space the application made it; `undefined` for a space created without one. */
  kind(): Promise<string | undefined> {
    return callAsync(() => this.#raw().kind() as Promise<string | undefined>);
  }

  /**
   * Whether this device keeps nothing of the space at rest: a guest whose grant carries
   * `frasil.nothing-at-rest`. Its content stays in memory only; keep none of it in the
   * application's own storage or caches either.
   */
  keepsNothingAtRest(): Promise<boolean> {
    return callAsync(() => this.#raw().keepsNothingAtRest() as Promise<boolean>);
  }

  /** This device's level in the space; `undefined` once it is no member. */
  level(): Promise<Level | undefined> {
    return callAsync(() => this.#raw().level() as Promise<Level | undefined>);
  }

  /** The space's members as this device's view of it has them. */
  members(): Promise<Member[]> {
    return callAsync(() => this.#raw().members() as Promise<Member[]>);
  }

  /** Every version tagged in the space, by name then ID. */
  versions(): Promise<Version[]> {
    return callAsync(() => this.#raw().versions() as Promise<Version[]>);
  }

  /** Removes a tag: a writer's change. */
  untag(version: VersionId): Promise<void> {
    return callAsync(() => this.#raw().untag(version) as Promise<void>);
  }

  /** The space's versions stream: a Records stream of Frasil's own, listed among the streams. */
  get versionsStream(): StreamId {
    return this.#raw().versionsStream as StreamId;
  }

  /**
   * Removes a member. The space rotates its keys, so the member reads nothing written after;
   * devices still connected heal and cascade by themselves.
   */
  remove(member: MemberId): Promise<void> {
    return callAsync(() => this.#raw().remove(member) as Promise<void>);
  }

  /**
   * The space's checkpoints as this device holds them: the one in effect, those waiting for votes
   * with whom each waits for, and what checkpoints made void. Rejects with `unknown_space`.
   */
  checkpoints(): Promise<CheckpointStatus> {
    return callAsync(() => this.#raw().checkpoints() as Promise<CheckpointStatus>);
  }

  /**
   * Proposes a checkpoint of the space now, whatever the device's checkpoint policy: once every
   * administrator has written anything after it, it takes effect, and every member may forget what
   * came before it. Resolves to its ID. Rejects with `not_allowed` unless this device administers
   * the space, while a checkpoint waits for votes, or while the device does not yet hold all the
   * space's past it needs.
   */
  proposeCheckpoint(): Promise<CheckpointId> {
    return callAsync(() => this.#raw().proposeCheckpoint() as Promise<CheckpointId>);
  }

  /**
   * This device's membership changes that a checkpoint made late and that it does not make again by
   * itself: grants and raised levels, which the administrator decides whether to make again. Late
   * removals and demotions are signed again by the device, and late edits sent again.
   */
  lateChanges(): Promise<LateChange[]> {
    return callAsync(() => this.#raw().lateChanges() as Promise<LateChange[]>);
  }

  /** The space's streams that this device holds a change of. */
  streams(): Promise<StreamInfo[]> {
    return callAsync(() => this.#raw().streams() as Promise<StreamInfo[]>);
  }

  /** Authored events awaiting flush's acknowledgement, including roster and key events. */
  pendingAuthoredChanges(): Promise<bigint> {
    return callAsync(() => this.#raw().pendingAuthoredChanges() as Promise<bigint>);
  }

  /**
   * Whether every change this device made in the space is durable: an always-on peer, or the
   * members it must reach, acknowledged it.
   */
  isDurable(): Promise<boolean> {
    return callAsync(() => this.#raw().isDurable() as Promise<boolean>);
  }

  /**
   * Sends every change this device made in the space that is not yet durable, and resolves once it
   * is, as {@link Space.isDurable} says: for example after {@link Space.setLevel}, before the
   * device closes or goes offline. Rejects with a connection error when the changes are not
   * durable within 30 seconds; they stay on this device, which sends them once it reaches a peer.
   */
  flush(): Promise<void> {
    return callAsync(() => this.#raw().flush() as Promise<void>);
  }

  /**
   * Resolves as soon as every change this device made in the space is durable, as
   * {@link Space.isDurable} says, without waiting for an administration connection to finish as
   * {@link Space.flush} does. Rejects with a connection error when the changes are not durable
   * within `withinMs` milliseconds; they stay on this device, which sends them once it reaches a
   * peer.
   */
  waitDurable(withinMs: number): Promise<void> {
    return callAsync(() => this.#raw().waitDurable(withinMs) as Promise<void>);
  }

  /**
   * Whether this device may write in the space as far as a restore goes: `true` unless the device
   * was opened as restored and has not synced the space since. Until then each write there rejects
   * with `sync_before_writing`. A browser's store opened in restore mode `never-restored` is never
   * restored; one opened in mode `none` is restored at every open. The device's level is a
   * separate question: see {@link Space.level}.
   */
  isWriteReady(): Promise<boolean> {
    return callAsync(() => this.#raw().isWriteReady() as Promise<boolean>);
  }

  /**
   * Resolves once this device may write in the space, as {@link Space.isWriteReady} says, and at
   * once when it already may. The device syncs the space on its own connections meanwhile. Rejects
   * with `sync_before_writing` when it has not synced the space within `withinMs` milliseconds, as
   * when no peer that holds the space is reachable.
   *
   * ```ts
   * await space.waitWriteReady(30_000);
   * await (await space.document(id)).edit((doc) => doc.getText("body").insert(0, "Hello"));
   * ```
   */
  waitWriteReady(withinMs: number): Promise<void> {
    return callAsync(() => this.#raw().waitWriteReady(milliseconds(withinMs)) as Promise<void>);
  }

  /**
   * Observes whether this device may write in the space, as {@link Space.isWriteReady} says:
   * `false` while a device opened as restored has not synced the space, then `true` once it has.
   * It changes at most once while the device is open.
   */
  observeWriteReady(): Observable<boolean> {
    return observe(
      () => this.isWriteReady(),
      (wake, fail) => {
        let stopped = false;
        const wait = (): void => {
          this.waitWriteReady(60_000).then(
            () => {
              if (!stopped) wake();
            },
            (error: unknown) => {
              if (stopped) return;
              if (
                error instanceof Error &&
                "code" in error &&
                error.code === "sync_before_writing"
              ) {
                wait();
              } else {
                fail(error);
              }
            },
          );
        };
        wait();
        return () => {
          stopped = true;
        };
      },
    );
  }

  /**
   * Pauses the space's sync with always-on peers, as for a suspended library: the device stores
   * nothing at a peer and fetches nothing from one for the space until {@link Space.resumeSync},
   * and the space stays readable and writable here. A pause lasts while the device is open.
   */
  pauseSync(): void {
    call(() => this.#raw().pauseSync());
  }

  /** Resumes the space's sync with always-on peers: it offers its heads and fetches what it lacks. */
  resumeSync(): void {
    call(() => this.#raw().resumeSync());
  }

  /** Whether the space's sync with always-on peers is paused. */
  isSyncPaused(): boolean {
    return call(() => this.#raw().isSyncPaused());
  }

  /**
   * Ends a session: every guest granted with `session`, 16 bytes, is removed in one change of the
   * membership, and reads nothing written after.
   */
  endSession(session: Uint8Array): Promise<void> {
    return callAsync(() => this.#raw().endSession(session) as Promise<void>);
  }

  /**
   * Admits the device whose {@link Joining.text} a newcomer shows, at `level`, through the exchange
   * mailbox at the peer that text names. Both screens then show the same six-digit code: `confirm`
   * is given it and the newcomer's name. `name` is what the newcomer's screen shows for this
   * device. The newcomer reads what is written from now on, unless `history` is `with-history`.
   */
  admit(
    code: string,
    level: Exclude<Level, "administer">,
    name: string,
    confirm: Confirm,
    options: { history?: HistoryMode } = {},
  ): Promise<void> {
    return callAsync(
      () => this.#raw().admit(code, level, name, confirm, options.history) as Promise<void>,
    );
  }

  /**
   * {@link Space.admit}, admitting the newcomer as an administrator at `rank`, 0 to 255, at most
   * this device's own: a larger rank outranks a smaller one. `admit` refuses `administer`, which
   * has no default rank.
   */
  admitAdministrator(
    code: string,
    rank: number,
    name: string,
    confirm: Confirm,
    options: { history?: HistoryMode } = {},
  ): Promise<void> {
    return callAsync(
      () =>
        this.#raw().admitAdministrator(code, rank, name, confirm, options.history) as Promise<void>,
    );
  }

  /**
   * Makes an invite link into the space at `level` (`read` or `write`), open for `lifetime`
   * seconds, 15 minutes to 7 days: whoever opens it joins with {@link Device.join}, with no administrator
   * online. Treat it as a password until it is used: the first device to claim it is admitted.
   * This device must be connected to a peer.
   *
   * With `claimant: "person"`, the link admits the person of the device that opens it, with every
   * device on the person's list, and that device hands the person's list to the space, so that an
   * administering device can change the person's level or remove the person later. Only a person's
   * device can claim such a link. The default, `"device"`, admits the claiming device alone.
   */
  inviteLink(
    level: Exclude<Level, "administer">,
    lifetime: number,
    options: { history?: HistoryMode; claimant?: "device" | "person" } = {},
  ): Promise<string> {
    return callAsync(
      () =>
        this.#raw().inviteLink(
          level,
          lifetime,
          options.history,
          options.claimant,
        ) as Promise<string>,
    );
  }

  /**
   * Revokes an invite link into the space that nobody has claimed yet: the space removes its
   * invite key, so a claim of it is refused from then on, and the drops of a link this device made
   * go from its peers. A link already claimed or revoked changes nothing. Rejects with
   * `not_allowed` unless this device administers the space, and `invalid_input` for a link into another
   * space.
   */
  revokeInviteLink(link: string): Promise<void> {
    return callAsync(() => this.#raw().revokeInviteLink(link) as Promise<void>);
  }

  /**
   * Exports the space to a file under the application's `kind` string: a space file carries one
   * space as a peer serves it, verified on import, plus a way in, so that a copy opens anywhere,
   * or a new device admits itself with nobody online. Resolves to the file's bytes, for the page
   * to save or send. Rejects with `not_allowed` while this device holds no current state of the
   * space, and `invalid_input` for an invite at `administer` or beyond 7 days.
   */
  exportSpaceFile(kind: string, options: SpaceFileExport = {}): Promise<Uint8Array> {
    return callAsync(() => this.#raw().exportSpaceFile(kind, options) as Promise<Uint8Array>);
  }

  /**
   * Appends what this device holds of the space since the file's last manifest, for a file this
   * space was exported to: resolves to the file's bytes, grown; nothing before is rewritten.
   * Rejects with `other_space` for a file of another space.
   */
  appendSpaceFile(file: Uint8Array): Promise<Uint8Array> {
    return callAsync(() => this.#raw().appendSpaceFile(file) as Promise<Uint8Array>);
  }

  /**
   * Whether this device writes here only suggestions, which stay out of the document or tables
   * until a writer accepts them: its grant, or its person's, carries `suggest` (see
   * {@link Space.setSuggester}). `false` for a full writer, an administrator and a reader.
   */
  canSuggest(): Promise<boolean> {
    return callAsync(() => this.#raw().canSuggest() as Promise<boolean>);
  }

  /**
   * Creates a restricted space under this one: a private part of it, which only devices that also
   * reach this space reach. Move documents into it with {@link LoroDocument.moveTo}.
   */
  async createRestricted(): Promise<Space> {
    return Space.wrap(
      await callAsync(() => this.#raw().createRestricted() as Promise<raw.Space>),
      this.device,
    );
  }

  /**
   * Grants a person, and so every device of theirs, at `read` or `write`; promote with
   * {@link Space.setLevel}.
   */
  grantPerson(person: PersonId, level: Exclude<Level, "administer">): Promise<void> {
    return callAsync(() => this.#raw().grantPerson(person, level) as Promise<void>);
  }

  /**
   * Admits a device that `knownSpace` grants directly to this space at `read` or `write`, by its
   * member ID, with no code: the grant carries the keys `knownSpace`'s roster names, with history,
   * and records `via` none. It commits at once; the device's welcome goes to its mailbox at this
   * device's peers, where its device collects it as it collects a person's grant. The grant rests
   * only on `knownSpace`'s roster: any administrator there could have put the device in it, and a
   * removal there does not reach this space, so an application that mirrors one space's members
   * into another mirrors removals too. Fails with `NotAllowed` unless this device administers the
   * space, when `knownSpace` does not grant the device directly or grants it as a guest, and when
   * this space has the device already.
   */
  admitMember(
    knownSpace: SpaceId,
    member: MemberId,
    level: Exclude<Level, "administer">,
  ): Promise<void> {
    return callAsync(() => this.#raw().admitMember(knownSpace, member, level) as Promise<void>);
  }

  /**
   * {@link Space.admitMember}, admitting the device as an administrator at `rank`, 0 to 255, at
   * most this device's own.
   */
  admitMemberAdministrator(knownSpace: SpaceId, member: MemberId, rank: number): Promise<void> {
    return callAsync(
      () => this.#raw().admitMemberAdministrator(knownSpace, member, rank) as Promise<void>,
    );
  }

  /**
   * Changes a member's level to `read` or `write`. The change goes to the space's peers at once;
   * {@link Space.flush} waits until one holds it. An administrator is made at a rank with
   * {@link Space.raise}.
   */
  setLevel(member: MemberId, level: Exclude<Level, "administer">): Promise<void> {
    return callAsync(() => this.#raw().setLevel(member, level) as Promise<void>);
  }

  /**
   * Raises a device member to `administer` at `rank`, 0 to 255, at most this device's own: a
   * larger rank outranks a smaller one, and nobody changes or removes an administrator of a higher
   * rank. The space's creator holds 255.
   */
  raise(member: MemberId, rank: number): Promise<void> {
    return callAsync(() => this.#raw().raise(member, rank) as Promise<void>);
  }

  /** Changes an administrator's rank: a lowering to `write`, then a raise at `rank`. */
  setRank(member: MemberId, rank: number): Promise<void> {
    return callAsync(() => this.#raw().setRank(member, rank) as Promise<void>);
  }

  /**
   * Makes a device member the space's recovery member: an administrator at the top rank marked
   * dormant, so that checkpoints do not wait for it and it can excuse and remove any member, a lost
   * top-rank device among them. Keep its device somewhere safe. Only a device at the top rank makes
   * one.
   */
  makeRecoveryMember(member: MemberId): Promise<void> {
    return callAsync(() => this.#raw().makeRecoveryMember(member) as Promise<void>);
  }

  /** Marks an administrator dormant, or no longer: a checkpoint does not wait for it. */
  setDormant(member: MemberId, dormant: boolean): Promise<void> {
    return callAsync(() => this.#raw().setDormant(member, dormant) as Promise<void>);
  }

  /** The space's recovery members: administrators marked dormant. */
  recoveryMembers(): Promise<MemberId[]> {
    return callAsync(() => this.#raw().recoveryMembers() as Promise<MemberId[]>);
  }

  /** A member's rank while it administers. */
  rank(member: MemberId): Promise<number | undefined> {
    return callAsync(() => this.#raw().rank(member) as Promise<number | undefined>);
  }

  /** This device's rank while it administers. */
  myRank(): Promise<number | undefined> {
    return callAsync(() => this.#raw().myRank() as Promise<number | undefined>);
  }

  /** Lets a member suggest changes for a writer to accept, or no longer. */
  setSuggester(member: MemberId, suggester: boolean): Promise<void> {
    return callAsync(() => this.#raw().setSuggester(member, suggester) as Promise<void>);
  }

  /**
   * Erases the whole space at its peers, which then refuse to keep it again, and drops it from this
   * device. What other members' devices keep is their own. Rejects with `not_allowed` unless this
   * device administers the space.
   */
  erase(): Promise<void> {
    return callAsync(() => this.#raw().erase() as Promise<void>);
  }

  /**
   * Leaves the space, then forgets it on this device. An administering device removes its person,
   * when its person is a member, then itself, and forgets the space once a connected peer holds
   * the removals. A member that does not administer sends a leave request to the administering
   * devices instead, and writes nothing there from then on; the space stays on this device until it
   * is removed or forgotten. Rejects with `not_allowed` for the last administering device, and with
   * `connection` when no connected peer holds the removals within 30 seconds: the space then stays
   * on this device, and a later call finishes leaving.
   */
  leave(): Promise<void> {
    return callAsync(() => this.#raw().leave() as Promise<void>);
  }

  /**
   * Forgets the space on this device: its log, streams and keys go, and `device.spaces()` no longer
   * lists it. The roster does not change; changes not yet durable at a peer are lost. Use it once
   * this device was removed (a `"removed"` event), or to stop holding a space.
   */
  forget(): Promise<void> {
    return callAsync(() => this.#raw().forget() as Promise<void>);
  }

  /** The space's ephemeral channel: messages to the members online now, kept nowhere. */
  ephemeral(): Ephemeral {
    return Ephemeral.wrap(call(() => this.#raw().ephemeral()));
  }

  /** Attaches the space to a library by the ticket its operator gave. */
  attachLibrary(ticket: Uint8Array): Promise<void> {
    return callAsync(() => this.#raw().attachLibrary(ticket) as Promise<void>);
  }

  /**
   * Keeps the home peer of the space's library: the URL of its origin, such as
   * `https://peer.example`, that the library's issuer returns beside the ticket, and after a move
   * the new home it names. The device names it first in each welcome it signs for the space, and
   * tries it first when a peer answers that it handed the space over; when no open connection
   * syncs the space, it syncs there now. It survives a restart.
   */
  setHomePeer(url: string): Promise<void> {
    return callAsync(() => this.#raw().setHomePeer(url) as Promise<void>);
  }

  /**
   * The always-on peers this device knows for the space, as origins' URLs, in the order it tries
   * them: the home peer first, then the peer hints its welcome named and the peers that granted
   * it the space, at most 8; a peer that answered that it handed the space over comes last.
   */
  knownPeers(): Promise<string[]> {
    return callAsync(() => this.#raw().knownPeers() as Promise<string[]>);
  }

  /** Creates a Loro document. It exists in the space from its first edit. */
  createDocument(): LoroDocument {
    return LoroDocument.wrap(
      call(() => this.#raw().createDocument()),
      this,
    );
  }

  /**
   * A Loro document of the space. Rejects with `unknown_stream` until this device holds a change
   * of it: a newcomer holds a stream from before its admission once a member writes there again.
   */
  async document(id: StreamId): Promise<LoroDocument> {
    return LoroDocument.wrap(
      await callAsync(() => this.#raw().document(id) as Promise<raw.Document>),
      this,
    );
  }

  /** Creates a set of Records tables. It exists in the space from its first write. */
  createRecords(): Records {
    return Records.wrap(
      call(() => this.#raw().createRecords()),
      this,
    );
  }

  /** Records tables of the space. Rejects with `unknown_stream` until this device holds a change. */
  async records(id: StreamId): Promise<Records> {
    return Records.wrap(
      await callAsync(() => this.#raw().records(id) as Promise<raw.Records>),
      this,
    );
  }

  /** Creates a blob stream. It exists in the space from its first blob. */
  createBlobs(): Blobs {
    return Blobs.wrap(
      call(() => this.#raw().createBlobs()),
      this,
    );
  }

  /** A blob stream of the space. Rejects with `unknown_stream` until this device holds a change. */
  async blobs(id: StreamId): Promise<Blobs> {
    return Blobs.wrap(await callAsync(() => this.#raw().blobs(id) as Promise<raw.Blobs>), this);
  }

  /**
   * Calls `callback` with each change of this space from now on, this device's own included: the
   * streams it changed, whether the members may have changed, and where it was made. Returns the
   * function that stops it. `onError` gets the error that ends it, if any.
   */
  onChange(
    callback: (change: SpaceChange) => void,
    onError?: (error: unknown) => void,
  ): () => void {
    return follow<SpaceChange>(
      call(() => this.#raw().changes()),
      callback,
      onError,
    );
  }

  /**
   * Observes a read of this space: `read` runs once the store has a subscriber, then again after
   * each change of the space, and subscribers hear of each result that differs. A read that rejects
   * with `unknown_stream`, or `missing` for bytes not held whole, shows as `"loading"`, so that a
   * read of something that has not arrived yet is no error.
   *
   * ```ts
   * const body = space.observe(async (space) => (await space.document(id)).text("body"));
   * ```
   */
  observe<T>(read: (space: Space) => Promise<T>): Observable<T> {
    return observe(
      () => read(this),
      (wake, fail) => this.onChange(() => wake(), fail),
    );
  }

  /**
   * A Loro document of the space, once this device holds it: at once if it does, else as soon as
   * a change of it arrives, for at most `withinMs`. Rejects with `timeout` when it has not arrived.
   */
  async documentWhenAvailable(id: StreamId, withinMs: number): Promise<LoroDocument> {
    return LoroDocument.wrap(
      await callAsync(
        () =>
          this.#raw().documentWhenAvailable(id, milliseconds(withinMs)) as Promise<raw.Document>,
      ),
      this,
    );
  }

  /** Records tables of the space, once this device holds them, as {@link Space.documentWhenAvailable}. */
  async recordsWhenAvailable(id: StreamId, withinMs: number): Promise<Records> {
    return Records.wrap(
      await callAsync(
        () => this.#raw().recordsWhenAvailable(id, milliseconds(withinMs)) as Promise<raw.Records>,
      ),
      this,
    );
  }

  /** A blob stream of the space, once this device holds it, as {@link Space.documentWhenAvailable}. */
  async blobsWhenAvailable(id: StreamId, withinMs: number): Promise<Blobs> {
    return Blobs.wrap(
      await callAsync(
        () => this.#raw().blobsWhenAvailable(id, milliseconds(withinMs)) as Promise<raw.Blobs>,
      ),
      this,
    );
  }
}

/** A space's ephemeral channel, from {@link Space.ephemeral}. */
export class Ephemeral extends Handle<raw.Ephemeral> {
  private constructor(value: raw.Ephemeral) {
    super(value, "Ephemeral");
  }

  /** @internal */
  static wrap(value: raw.Ephemeral): Ephemeral {
    return new Ephemeral(value);
  }

  /** Sends a message to the members online now. */
  send(message: Uint8Array): Promise<void> {
    return callAsync(() => this.raw().send(message) as Promise<void>);
  }

  /**
   * Calls `callback` with each message another member sends from now on, and its sender's device. Returns
   * the function that stops it. `onError` gets the error that ends it, if any.
   */
  subscribe(
    callback: (from: MemberId, message: Uint8Array) => void,
    onError?: (error: unknown) => void,
  ): () => void {
    const stream = call(() => this.raw().subscribe());
    return follow<{ from: MemberId; data: Uint8Array }>(
      stream,
      ({ from, data }) => callback(from, data),
      onError,
    );
  }
}
