/**
 * The device, its connections to always-on peers, its events, and the advanced calls beside it.
 *
 * @module
 */

import { FrasilError } from "./errors.js";
import { call, callAsync, Handle, raw } from "./runtime.js";
import {
  type CheckpointId,
  type ImportedSpaceFile,
  type LateChange,
  type Level,
  Space,
  type SpaceFileInfo,
  type SpaceId,
} from "./space.js";

import { IndexedDbStore, Storage } from "./stores.js";

/**
 * A recovery sheet (identity.md, "Recovery keys"): the recovery key's secret, the person and the
 * personal space. Show or print {@link RecoverySheet.text} once; the device forgets the secret.
 */
export interface RecoverySheet {
  /** The sheet as text, for {@link Device.recover}. */
  readonly text: string;
  /** The secret in its printed form: 55 characters in groups of four joined by `-`. */
  readonly secret: string;
  /** The person. */
  readonly person: MemberId;
  /** The person's personal space. */
  readonly personalSpace: SpaceId;
}

/**
 * A member's ID, as 64 hex digits: a device's device ID, the hash of its Ed25519 key and the
 * commitment to its other keys, or a person's ID. Show and compare members by it; a device's
 * Ed25519 key never names it.
 */
export type MemberId = string;

/** A person's ID, as 64 hex digits. */
export type PersonId = string;

/**
 * A person's confirmation of an admission: given the code both screens show (empty for an invite
 * link) and the other device's name or ID, it returns `true`, or a promise of `true`, when the
 * person saw the code on both screens or consents. Return a promise to show the code and wait for
 * the person's answer. Anything else, a throw or a rejection included, declines.
 */
export type Confirm = (code: string, name: string) => boolean | Promise<boolean>;

/** Headers that sign an application request, as `[name, value]` pairs to add to it. */
export type SignedHeaders = [string, string][];

/** How a device runs. The defaults suit an application; each setting changes one thing. */
export interface Options {
  /**
   * `never-restored` (the default): the application states that its browser storage is never
   * restored from a backup, as a browser has no place that no backup restores. `none`: every start
   * counts as a restore, and the device syncs each space before it writes there again.
   */
  readonly restoreMode?: "never-restored" | "none";
  /** Whether the wall clock counts as known (overview.md, "Clocks"). Default `true`. */
  readonly wallClockKnown?: boolean;
  /**
   * A library ticket (ext-libraries.md) for the next space the device creates at a peer that
   * requires one; {@link Device.setLibraryTicket} sets one later.
   */
  readonly libraryTicket?: Uint8Array;
  /**
   * The budget of the blob cache, in stored bytes: 268,435,456 (256 MiB) unless given. A read
   * leaves the blobs it fetches in the cache, and the device drops whole cached blobs, the one
   * read longest ago first, to stay within the budget. With 0 nothing is cached: a read passes
   * its blob through memory. Kept blobs and the blobs this device put are outside it.
   *
   * Over an {@link IndexedDbStore} the budget is lowered to half of what the browser says the
   * origin may still store (`navigator.storage.estimate()`: its quota less its usage, plus what
   * the cache holds already), where the browser says so. {@link Device.blobCacheUsage} gives
   * the budget in force.
   */
  readonly blobCache?: number;
  /**
   * Keeps every blob the device fetches, and fetches every blob of its spaces by itself: nothing
   * is evicted, and `blobCache` counts for nothing.
   */
  readonly keepAllBlobs?: boolean;
}

/** The budget of the blob cache and what the device's blobs take, from {@link Device.blobCacheUsage}. */
export interface BlobCacheUsage {
  /** The budget of the cache in force, in stored bytes. */
  readonly budget: number;
  /**
   * The stored bytes of the cached blobs, whole or in part: within the budget, but for what
   * running reads hold beside the cache.
   */
  readonly cached: number;
  /** The stored bytes of the blobs the device keeps, outside the budget. */
  readonly kept: number;
}

/** The share of what the origin may still store that the blob cache takes at most. */
const QUOTA_SHARE = 0.5;

/**
 * Lowers a device's blob cache budget to {@link QUOTA_SHARE} of what the browser says the origin
 * may still store, counting what the cache holds already as room. Nothing changes where the
 * browser gives no estimate, or one with no quota, or for a device that keeps every blob.
 */
async function withinQuota(device: raw.Device, options: Options): Promise<void> {
  if (options.keepAllBlobs) return;
  let estimate: StorageEstimate | undefined;
  try {
    estimate = await globalThis.navigator?.storage?.estimate?.();
  } catch {
    return;
  }
  const quota = estimate?.quota;
  if (quota === undefined || !Number.isFinite(quota) || quota <= 0) return;
  const usage = await callAsync(() => device.blobCacheUsage() as Promise<BlobCacheUsage>);
  const room = Math.max(0, quota - (estimate?.usage ?? 0)) + usage.cached;
  const cap = Math.floor(room * QUOTA_SHARE);
  if (cap < usage.budget) call(() => device.setBlobCache(cap));
}

/**
 * A Frasil device: its keys, its store, the spaces it holds, and its connections. Open it once per
 * page with {@link Device.open}. While it is open it runs its own upkeep (sync, durability, and
 * the heals and cascades that keep keys current) on the page's event loop; {@link Device.close}
 * stops it.
 */
export class Device extends Handle<raw.Device> {
  readonly #id: MemberId;

  private constructor(value: raw.Device) {
    super(value, "Device");
    this.#id = value.id;
  }

  /**
   * Opens the device kept in `storage`, or creates one there if it holds none. `unlockKey` seals
   * the device's keys: 32 bytes of high entropy, such as a passkey's PRF output, never a password,
   * and never stored beside the store.
   */
  static async open(
    storage: Storage,
    unlockKey: Uint8Array,
    options: Options = {},
  ): Promise<Device> {
    const store = await Storage.open(storage);
    const sealed = (await store.loadSealedKeys()) ?? undefined;
    const opened = await callAsync(
      () =>
        raw.Device.open(store, unlockKey, sealed, options) as Promise<{
          device: raw.Device;
          sealedKeys: Uint8Array;
        }>,
    );
    if (sealed === undefined) await store.saveSealedKeys(opened.sealedKeys);
    if (store instanceof IndexedDbStore) await withinQuota(opened.device, options);
    const device = new Device(opened.device);
    if (options.libraryTicket !== undefined) device.setLibraryTicket(options.libraryTicket);
    return device;
  }

  /**
   * Makes a new device of a person from a recovery sheet's text, in `storage`, which must hold no
   * device, with its keys sealed under `unlockKey` (identity.md, "Recovery"). The device connects
   * to the peer at `peerUrl`, which holds the person's personal space, fetches the space through
   * the recovery key's entry, signs itself into the person's list, and reaches every space the
   * personal space records a recovery entry of. Rejects with `invalid_sheet` for a secret that
   * does not read, `credential_refused` when the peer holds no entry of the sheet's key,
   * `not_on_list`, or `timeout`.
   *
   * Recovering with a passkey is not in this package yet: the client takes a passkey as an object
   * whose `register` and `assert` map to WebAuthn with the PRF extension.
   */
  static async recover(
    storage: Storage,
    unlockKey: Uint8Array,
    sheet: string,
    peerUrl: string,
    options: Options = {},
  ): Promise<Device> {
    const store = await Storage.open(storage);
    if ((await store.loadSealedKeys()) !== undefined) {
      throw new FrasilError("not_allowed", "recover: the storage already holds a device", {
        whatToDo: "recover into a storage of its own",
      });
    }
    const recovered = await callAsync(
      () =>
        raw.Device.recover(store, unlockKey, sheet, peerUrl, options) as Promise<{
          device: raw.Device;
          sealedKeys: Uint8Array;
        }>,
    );
    await store.saveSealedKeys(recovered.sealedKeys);
    if (store instanceof IndexedDbStore) await withinQuota(recovered.device, options);
    const device = new Device(recovered.device);
    return device;
  }

  /**
   * Adds a recovery key to this device's person, and resolves to its sheet: show or print it once,
   * since the device forgets the secret. The person's spaces wrap their keys for the recovery key
   * from now on, and the device's peer connections register its entries. Rejects with
   * `not_allowed` for a device of no person.
   */
  createRecoverySheet(): Promise<RecoverySheet> {
    return callAsync(() => this.raw().createRecoverySheet() as Promise<RecoverySheet>);
  }

  /** The device's ID, by which spaces name it as a member. */
  get id(): MemberId {
    return this.#id;
  }

  /**
   * The device's person, whose devices a space can grant at once ({@link Space.grantPerson});
   * `null` for a device of no person ({@link Device.makePerson} makes one).
   */
  person(): Promise<PersonId | null> {
    return callAsync(() => this.raw().person() as Promise<PersonId | null>);
  }

  /**
   * The personal space of the device's person (identity.md, "The person ID and the personal
   * space"), once the device knows it: it made the person or recovered into it, and still knows
   * it after a reload. `null` for a device of no person, and while the device cannot tell which
   * space it is.
   */
  personalSpace(): Promise<SpaceId | null> {
    return callAsync(() => this.raw().personalSpace() as Promise<SpaceId | null>);
  }

  /**
   * Makes a person of this device (identity.md, "Making a person"): its device list and its
   * personal space. Call it on first run, before {@link Device.createSpace}, so that the spaces
   * it creates grant the person. The device's keys are sealed again under `unlockKey`, the key it
   * was opened with, and kept in its storage in place of the old ones. Idempotent: resolves to the
   * person it is a device of already.
   */
  async makePerson(unlockKey: Uint8Array): Promise<PersonId> {
    return (await this.advanced.makePerson(unlockKey)).person;
  }

  /**
   * Joins a space by an invite link that {@link Space.inviteLink} made: the device fetches the
   * link's drop from the peer the link names, or a peer it is connected to, and the space with it.
   * `confirm` is given an empty code and the inviting device's ID, and returns `true` for the
   * person's consent. `name` is what the inviting side shows for this device. Rejects with
   * `invite_used`, `invite_revoked`, `invite_raced` or `expired` for a link that can no longer be
   * claimed.
   */
  async join(link: string, name: string, confirm: Confirm): Promise<Space> {
    return Space.wrap(
      await callAsync(() => this.raw().join(link, name, confirm) as Promise<raw.Space>),
      this,
    );
  }

  /**
   * Imports a space file whose kind is `kind`, one string or any of several, by the road the file
   * allows: a space this device holds already is merged (`member`, or `rereading` when it holds
   * it by keys alone); the file's invite, if any, admits this device with nobody online, once the
   * person consents (`invited`, with a {@link SpaceFileInvitation} to show, then accept or
   * decline); else the file's keys let it read for as long as the file exists (`reading`). Every
   * event, unit and object is verified as sync verifies it; nothing is trusted on the file's
   * say-so. `key`, 32 bytes, opens a way in sealed under a file key. Rejects with
   * `not_a_space_file`, `wrong_kind`, `sealed` for a sealed way in without its key, `decrypt` with
   * the wrong one, `no_way_in`, and, for a file whose every invite is spent and that carries no
   * keys, the last refusal such as `invite_used`.
   */
  async importSpaceFile(
    file: Uint8Array,
    kind: string | string[],
    options: { key?: Uint8Array } = {},
  ): Promise<ImportedSpaceFile> {
    const imported = await callAsync(
      () =>
        this.raw().importSpaceFile(file, kind, options.key) as Promise<
          | { road: "member" | "rereading" | "reading"; space: raw.Space }
          | { road: "invited"; invitation: raw.Invitation }
        >,
    );
    if (imported.road === "invited") {
      return { road: "invited", invitation: SpaceFileInvitation.wrap(imported.invitation, this) };
    }
    return { road: imported.road, space: Space.wrap(imported.space, this) };
  }

  /**
   * Reads what a space file says of itself, with no event read and nothing opened: its space,
   * kind, history, how many objects it embeds, and whether it carries a way in. The bytes need
   * not be the whole file: the magic and the first segment suffice. Throws `not_a_space_file`
   * for anything else.
   */
  static sniffSpaceFile(file: Uint8Array): SpaceFileInfo {
    return call(() => raw.Device.sniffSpaceFile(file) as SpaceFileInfo);
  }

  /**
   * Grants a previously authenticated direct member of `knownSpace` Administer in each target,
   * at `rank` (at most this device's own in each), with history. Reports each atomic grant and its mailbox delivery independently. Retry failed
   * or unfinished spaces after reconnecting, even when `granted` is true. Select the device by
   * its authenticated ID. The recipient calls receiveSpacesViaPeer; no new code exchange is needed.
   */
  admitSpacesViaPeer(
    url: string,
    knownSpace: SpaceId,
    member: MemberId,
    rank: number,
    spaces: SpaceId[],
    progress?: (report: SpaceAdmission) => void,
  ): Promise<SpaceAdmission[]> {
    return callAsync(
      () =>
        this.raw().admitSpacesViaPeer(url, knownSpace, member, rank, spaces, progress) as Promise<
          SpaceAdmission[]
        >,
    );
  }

  /** Collects and verifies Administer welcomes for exactly these spaces from a known approver. */
  receiveSpacesViaPeer(
    url: string,
    approver: MemberId,
    spaces: SpaceId[],
    progress?: (report: SpaceAdmission) => void,
  ): Promise<SpaceAdmission[]> {
    return callAsync(
      () =>
        this.raw().receiveSpacesViaPeer(url, approver, spaces, progress) as Promise<
          SpaceAdmission[]
        >,
    );
  }

  /**
   * Joins a space through an exchange mailbox at the peer at `peerUrl`, as a browser does without a
   * nearby connection. Show the {@link Joining.text} as a QR code; an administrator enters it in
   * {@link Space.admit}. Both screens then show the same six-digit code: `confirm` is given it and
   * the administrator's device name. {@link Joining.joined} waits for the space.
   */
  async joinViaPeer(peerUrl: string, name: string, confirm: Confirm): Promise<Joining> {
    const joining = await callAsync(
      () => this.raw().joinViaPeer(peerUrl, name, confirm) as Promise<raw.Joining>,
    );
    return Joining.wrap(joining, this);
  }

  /**
   * Joins `person` as its new device through an exchange mailbox at the peer at `peerUrl`
   * (admission.md, "A person's new device"), as a browser does without a nearby connection. A
   * device of another person that answers adds this device to no list, and
   * {@link JoiningPerson.joined} rejects with `wrong_person`. Show
   * the {@link JoiningPerson.text} as a QR code; a device of the person enters it in
   * {@link Device.admitDevice}. Both screens then show the same six-digit code: `confirm` is given
   * it and the other device's name. `unlockKey` is the key this device was opened with: once
   * admitted, its keys are sealed again under it to name the person, and kept in its storage in
   * place of the old ones, as {@link Device.makePerson} keeps them. {@link JoiningPerson.joined}
   * waits for the person's spaces. Rejects with `not_allowed` for a device of a person already.
   */
  async joinPersonViaPeer(
    peerUrl: string,
    person: MemberId,
    name: string,
    unlockKey: Uint8Array,
    confirm: Confirm,
  ): Promise<JoiningPerson> {
    const joining = await callAsync(
      () =>
        this.raw().joinPersonViaPeer(
          peerUrl,
          person,
          name,
          unlockKey,
          confirm,
        ) as Promise<raw.JoiningPerson>,
    );
    return JoiningPerson.wrap(joining, this);
  }

  /**
   * Adds the device whose {@link JoiningPerson.text} a new device shows to this device's person,
   * through the exchange mailbox at the peer that text names. Both screens then show the same
   * six-digit code: `confirm` is given it and the new device's name. `name` is what the new
   * device's screen shows for this device. The new device then reaches every space this device
   * writes in that grants the person. Rejects with `not_allowed` for a device of no person,
   * `mismatch` when the person did not confirm the code, `cancelled`, `expired` or `timeout`.
   */
  admitDevice(text: string, name: string, confirm: Confirm): Promise<void> {
    return callAsync(() => this.raw().admitDevice(text, name, confirm) as Promise<void>);
  }

  /**
   * Signs a request to an application's server (ext-app-requests.md), which verifies it with
   * `verifySignedRequest` from `@frasil/client/module`. `subject` is the access token's `sub`,
   * `url` the absolute URL, `body` the exact bytes sent. Resolves to the headers to add; they live
   * 60 seconds. The HTTP client must follow no redirect. Rejects with `not_allowed` for a device
   * of no person.
   */
  signRequest(
    subject: string,
    method: string,
    url: string,
    body: Uint8Array = new Uint8Array(),
  ): Promise<SignedHeaders> {
    return callAsync(
      () => this.raw().signRequest(subject, method, url, body) as Promise<SignedHeaders>,
    );
  }

  /**
   * The list delivery of this device's person (ext-app-requests.md, "The list delivery"): every
   * event of its device list, as the body of a signed `PUT /frasil/p1/device-list` at the
   * verifier's origin, with `Content-Type: application/cbor`. Send it when a verifier refuses
   * `device_list_needed`, then sign the request again and retry it once. Rejects with
   * `not_allowed` for a device of no person.
   */
  listDelivery(): Promise<Uint8Array> {
    return callAsync(() => this.raw().listDelivery() as Promise<Uint8Array>);
  }

  /**
   * Takes another device of this device's person off the person's device list, so it reaches none
   * of the person's spaces any more; each of them rotates its keys. It is also removed from each
   * space this device administers that grants it directly. Rejects with `invalid_input` for this device
   * itself, `not_allowed` for a device of no person, and `not_in_list` for a device not on the
   * list.
   */
  removeDevice(device: MemberId): Promise<void> {
    return callAsync(() => this.raw().removeDevice(device) as Promise<void>);
  }

  /**
   * A 32-byte key for the application's own data on this device, such as a cache it keeps at rest:
   * `purpose` names what it is for, such as `"com.example.cache"`, and each purpose gives a key of
   * its own. The same device gives the same key for the same purpose after every restart. It
   * reveals none of the device's keys, and no other device can derive it. Rejects with `invalid`
   * for an empty purpose.
   */
  deriveKey(purpose: string): Promise<Uint8Array> {
    return callAsync(() => this.raw().deriveKey(purpose) as Promise<Uint8Array>);
  }

  /**
   * Creates a space that this device administers, as {@link Device.createSpace} does, whose
   * descriptor names `kind`: what kind of space the application makes, such as `"notes"`. It never
   * changes, every member reads it with {@link Space.kind}, and no peer does. Rejects with
   * `invalid` for a kind that is empty or longer than 255 bytes.
   */
  async createSpaceOfKind(kind: string): Promise<Space> {
    return Space.wrap(
      await callAsync(() => this.raw().createSpaceOfKind(kind) as Promise<raw.Space>),
      this,
    );
  }

  /** Creates a space that this device administers, and presents it to every connected peer. */
  async createSpace(): Promise<Space> {
    return Space.wrap(await callAsync(() => this.raw().createSpace() as Promise<raw.Space>), this);
  }

  /** Asks the saved peers again about a retained erasure. */
  async retryErasure(id: SpaceId): Promise<void> {
    await callAsync(() => this.raw().retryErasure(id) as Promise<void>);
  }

  /**
   * Gives up a space this device dropped for its own erasure: it no longer waits for each peer to
   * answer that it erased the space, and forgets what it kept of it. The space may live on at the
   * peers that did not answer. Rejects with `unknown_space` for a space it did not drop so.
   */
  async giveUpSpace(id: SpaceId): Promise<void> {
    await callAsync(() => this.raw().giveUpSpace(id) as Promise<void>);
  }

  /** A space the device holds. Rejects with `unknown_space` if it holds none of this ID. */
  async space(id: SpaceId): Promise<Space> {
    return Space.wrap(await callAsync(() => this.raw().space(id) as Promise<raw.Space>), this);
  }

  /** Every space the device holds. */
  async spaces(): Promise<Space[]> {
    const spaces = await callAsync(() => this.raw().spaces() as Promise<raw.Space[]>);
    return spaces.map((space) => Space.wrap(space, this));
  }

  /**
   * Connects to an always-on peer at its URL, such as `https://peer.example.org` (plain `http`
   * only to a loopback host), and keeps every space the device holds there: the connection syncs
   * them both ways, live, and the peer's acknowledgements make this device's changes durable.
   * Spaces the device creates later are presented too. Resolves once the handshake completes.
   */
  async connect(url: string): Promise<Peer> {
    return Peer.wrap(await callAsync(() => this.raw().connect(url) as Promise<raw.Peer>));
  }

  /**
   * Pauses the sync of these spaces with always-on peers at once, such as every space of one
   * library its operator suspended: {@link Space.pauseSync} for each. The client never learns
   * which library a space is billed to, so the application names the spaces.
   */
  pauseSync(spaces: readonly (Space | SpaceId)[]): void {
    call(() => this.raw().pauseSync(spaces.map(idOf)));
  }

  /** Resumes the sync of these spaces with always-on peers: {@link Space.resumeSync} for each. */
  resumeSync(spaces: readonly (Space | SpaceId)[]): void {
    call(() => this.raw().resumeSync(spaces.map(idOf)));
  }

  /** The peers the device has connected to, open or closed. */
  peers(): Peer[] {
    return call(() => this.raw().peers() as raw.Peer[]).map((peer) => Peer.wrap(peer));
  }

  /** The device's events, from now on: what changed in its spaces. */
  events(): Events {
    return Events.wrap(call(() => this.raw().events()));
  }

  /**
   * Keeps a library ticket (ext-libraries.md) for the next space this device creates at a peer that
   * requires one. A ticket attaches one space. Throws `invalid_input` for bytes that are no create
   * ticket.
   */
  setLibraryTicket(ticket: Uint8Array): void {
    call(() => this.raw().setLibraryTicket(ticket));
  }

  /**
   * Hands the device a deposit grant for the peer at `peer`: the bytes the library's issuer gave
   * the application (ext-deposit-tokens.md, 3.1.1). The device never reads, stores or shows it.
   * Within the hour, at a random moment, it draws one batch of 16 tokens with it at that peer,
   * unless it holds enough there already, then forgets it. It pays with a token for each deposit in
   * a device mailbox there, such as a welcome, which a stranger then cannot crowd out.
   */
  giveDepositGrant(peer: string, grant: Uint8Array): void {
    call(() => this.raw().giveDepositGrant(peer, grant));
  }

  /** How many deposit tokens the device holds for the peer at `peer`, and whether it draws there. */
  depositTokens(peer: string): Promise<DepositTokens> {
    return callAsync(() => this.raw().depositTokens(peer) as Promise<DepositTokens>);
  }

  /**
   * Trusts the deposit keys of the peer at `peer` again after a {@link DepositPeerDistrustedEvent}
   * with `key_inconsistent`: the device forgets what it saw there and learns the keys anew. Call it
   * only when a person decided so: a peer that shows devices different keys can tell their
   * deposits apart.
   */
  trustDepositKeys(peer: string): Promise<void> {
    return callAsync(() => this.raw().trustDepositKeys(peer) as Promise<void>);
  }

  /**
   * How many deposits in device mailboxes, such as welcomes, the device keeps to send again: a peer
   * answered `busy` or `rate_limited`, or was not reached. It sends them again by itself for up to
   * 30 days; {@link DelayedEvent} and {@link DeliveredEvent} report them.
   */
  waitingDeposits(): Promise<number> {
    return callAsync(() => this.raw().waitingDeposits() as Promise<number>);
  }

  /**
   * Sets what the device does about checkpoints by itself: whether it proposes them when a space's
   * history, or its person's device list, calls for one, and whether it forgets what came before
   * one in effect. Each field left out takes the default's value: proposing and forgetting, at
   * {@link PROPOSE_AT_ROSTER_EVENTS} roster events or {@link PROPOSE_AT_FRAME_BYTES} bytes of frame
   * events. A threshold of 0 counts as 1.
   */
  setCheckpointPolicy(policy: Partial<CheckpointPolicy>): void {
    call(() => this.raw().setCheckpointPolicy(policy));
  }

  /** The device's checkpoint policy. */
  checkpointPolicy(): CheckpointPolicy {
    return call(() => this.raw().checkpointPolicy() as CheckpointPolicy);
  }

  /**
   * Proposes a checkpoint of this device's person's device list now, whatever the device's
   * checkpoint policy. Resolves to its ID. Rejects with `not_allowed` for a device of no person,
   * and with `checkpoint_pending` while a list checkpoint waits for votes.
   */
  proposeListCheckpoint(): Promise<CheckpointId> {
    return callAsync(() => this.raw().proposeListCheckpoint() as Promise<CheckpointId>);
  }

  /**
   * The checkpoints of this device's person's device list: the one in effect, those waiting for
   * votes with whom each waits for, and whether the device forgot the list's earlier events. None
   * for a device of no person.
   */
  listCheckpoints(): Promise<ListCheckpointStatus> {
    return callAsync(() => this.raw().listCheckpoints() as Promise<ListCheckpointStatus>);
  }

  /**
   * The budget of the blob cache, and what the device's cached and kept blobs take, in stored
   * bytes, across all its spaces.
   */
  blobCacheUsage(): Promise<BlobCacheUsage> {
    return callAsync(() => this.raw().blobCacheUsage() as Promise<BlobCacheUsage>);
  }

  /** Closes the device: stops its upkeep and its connections. It can still be read. */
  close(): Promise<void> {
    return callAsync(() => this.raw().close() as Promise<void>);
  }

  /**
   * Lower-level calls, less stable than the rest: the direct grant, by which a browser admits
   * another device, and the device's signed events.
   */
  get advanced(): Advanced {
    return new Advanced(this);
  }
}

/**
 * An invite a space file carries for this device, prepared and checked, waiting for the person's
 * consent, from {@link Device.importSpaceFile}. Show the inviter, the level and the label, then
 * {@link SpaceFileInvitation.accept} or {@link SpaceFileInvitation.decline}. Left undecided, the
 * claim waits in the device: the space is not listed, no peer is told of it, importing the file
 * again offers it again, and a device that stops meanwhile forgets it when it next opens. An
 * `accept` that rejects leaves the invitation to decline.
 */
export class SpaceFileInvitation extends Handle<raw.Invitation> {
  readonly #device: Device;
  /** The space the file carries. */
  readonly space: SpaceId;
  /** The inviting device's ID. */
  readonly inviter: MemberId;
  /** The level the claim gives. */
  readonly level: Exclude<Level, "administer">;
  /** When the invite expires, as seconds since the epoch. */
  readonly expiresAt: number;
  /** The way in's label, if the exporter wrote one: what the file is for. */
  readonly label: string | undefined;

  private constructor(value: raw.Invitation, device: Device) {
    super(value, "SpaceFileInvitation");
    this.#device = device;
    this.space = value.space;
    this.inviter = value.inviter;
    this.level = value.level as Exclude<Level, "administer">;
    this.expiresAt = value.expiresAt;
    this.label = value.label ?? undefined;
  }

  /** @internal */
  static wrap(value: raw.Invitation, device: Device): SpaceFileInvitation {
    return new SpaceFileInvitation(value, device);
  }

  /**
   * The person consents: the device signs itself in and writes from now on; its successor reaches
   * the others when it next meets a member or a peer. Rejects with a claim's refusal, such as
   * `invite_used`, should the invite have been spent meanwhile.
   */
  async accept(): Promise<Space> {
    return Space.wrap(
      await callAsync(() => this.raw().accept() as Promise<raw.Space>),
      this.#device,
    );
  }

  /** The person declines: nothing of the file is kept. */
  decline(): Promise<void> {
    return callAsync(() => this.raw().decline() as Promise<void>);
  }
}

/** A newcomer's admission through an exchange mailbox, from {@link Device.joinViaPeer}. */
export class Joining extends Handle<raw.Joining> {
  readonly #device: Device;
  readonly #text: string;

  private constructor(value: raw.Joining, device: Device) {
    super(value, "Joining");
    this.#device = device;
    this.#text = value.text;
  }

  /** @internal */
  static wrap(value: raw.Joining, device: Device): Joining {
    return new Joining(value, device);
  }

  /** The text an administrator enters in {@link Space.admit}: show it as a QR code. */
  get text(): string {
    return this.#text;
  }

  /**
   * Waits until an administrator has admitted this device and the space has arrived. Once only.
   * Rejects with `mismatch` when the person did not confirm the code, `cancelled`, `expired`, or
   * `timeout`.
   */
  async joined(): Promise<Space> {
    return Space.wrap(
      await callAsync(() => this.raw().joined() as Promise<raw.Space>),
      this.#device,
    );
  }
}

/**
 * A new device's admission to its person through an exchange mailbox, from
 * {@link Device.joinPersonViaPeer}.
 */
export class JoiningPerson extends Handle<raw.JoiningPerson> {
  readonly #device: Device;
  readonly #text: string;

  private constructor(value: raw.JoiningPerson, device: Device) {
    super(value, "JoiningPerson");
    this.#device = device;
    this.#text = value.text;
  }

  /** @internal */
  static wrap(value: raw.JoiningPerson, device: Device): JoiningPerson {
    return new JoiningPerson(value, device);
  }

  /** The text a device of the person enters in {@link Device.admitDevice}: show it as a QR code. */
  get text(): string {
    return this.#text;
  }

  /**
   * Waits until this device is one of the person's ({@link Device.person}) and the spaces that
   * grant the person have arrived; resolves to them. Once only. Rejects with `mismatch` when the
   * person did not confirm the code, `cancelled`, `expired`, or `timeout`.
   */
  async joined(): Promise<Space[]> {
    const spaces = await callAsync(() => this.raw().joined() as Promise<raw.Space[]>);
    return spaces.map((space) => Space.wrap(space, this.#device));
  }
}

/**
 * A device's three public keys, 3,200 bytes: its Ed25519, ML-DSA-65 and X-Wing keys, as a direct
 * grant carries them. They name no device: a grant takes them only under the device's
 * {@link MemberId}, which they hash to.
 */
export type DeviceKeys = Uint8Array;

/**
 * A guest's terms (ext-guests.md, "The guest preset"): a guest reaches one space, receives what is
 * shared from now on, and leaves when its session ends.
 */
export interface GuestTerms {
  /** `read` or `write`; a guest never administers. */
  readonly level: "read" | "write";
  /** The session's 16 random bytes, drawn once per session; `Space.endSession` names them. */
  readonly session: Uint8Array;
  /** The session's lifetime in seconds, at most 30 days, if it ends by itself. */
  readonly lifetime?: number;
  /** Whether the guest's device keeps nothing of the space at rest. */
  readonly nothingAtRest?: boolean;
  /**
   * `from-now-on`, the default: the guest reads only what is shared after its admission, and
   * starts from a snapshot. `with-history` hands it the space's earlier keys too.
   */
  readonly history?: HistoryMode;
}

/** Whether a direct grant reaches the space's earlier keys (roster.md, "Changes"). */
export type HistoryMode = "with-history" | "from-now-on";

/** What {@link Advanced.ingest} did. */
export interface Ingested {
  /** How many events were newly placed. */
  readonly placed: number;
  /** How many parents the device still waits for. */
  readonly wanted: number;
  /** Each refused event's index in the input, and its class. */
  readonly refused: [number, string][];
}

/**
 * The device's lower-level calls, from {@link Device.advanced}. Admission by code needs a nearby
 * connection, which a browser does not have; here a device admits another by a direct grant
 * instead:
 *
 * 1. the newcomer hands over its {@link Device.id} and {@link Advanced.deviceKeys};
 * 2. a device that administers the space calls {@link Advanced.grantDevice}, and hands over the
 *    space's ID and {@link Advanced.signedEvents}, which carry the newcomer's keys;
 * 3. the newcomer calls {@link Advanced.follow} and {@link Advanced.ingest}, then connects to the
 *    peer that keeps the space, which syncs it from there.
 */
export class Advanced {
  readonly #device: Device;

  /** @internal */
  constructor(device: Device) {
    this.#device = device;
  }

  #raw(): raw.Device {
    return Handle.rawOf(this.#device);
  }

  /**
   * Makes a person of this device (identity.md, "Making a person"): its device list and its
   * personal space. The device's keys are sealed again under `unlockKey` to name the person, and
   * kept in its storage in place of the old ones. For a device of a person already, it resolves to
   * that person alone. {@link Device.makePerson} is the same, resolving to the person.
   */
  async makePerson(unlockKey: Uint8Array): Promise<{ person: PersonId; personalSpace?: SpaceId }> {
    const made = await callAsync(
      () =>
        this.#raw().makePerson(unlockKey) as Promise<{
          person: PersonId;
          personalSpace?: SpaceId;
        }>,
    );
    return made.personalSpace === undefined
      ? { person: made.person }
      : { person: made.person, personalSpace: made.personalSpace };
  }

  /** The device's three public keys, for another device to grant it under {@link Device.id}. */
  deviceKeys(): DeviceKeys {
    return call(() => this.#raw().deviceKeys() as DeviceKeys);
  }

  /** `Current`, or `Restored`: the store is not the one the device last wrote. */
  continuity(): Promise<"Current" | "Restored"> {
    return callAsync(() => this.#raw().continuity() as Promise<"Current" | "Restored">);
  }

  /**
   * Grants a device directly into a space this device administers: its ID, which the application
   * learned in a way it trusts, and its keys from {@link Advanced.deviceKeys}, at `level`. Keys
   * that do not hash to the ID are refused (`NotCommitted`). Resolves to the roster event's ID.
   */
  grantDevice(
    space: Space | SpaceId,
    member: MemberId,
    keys: DeviceKeys,
    level: Level,
    history: HistoryMode = "with-history",
  ): Promise<string> {
    return callAsync(
      () => this.#raw().grantDevice(idOf(space), member, keys, level, history) as Promise<string>,
    );
  }

  /**
   * Grants a guest directly into a space this device administers: its ID, its keys from
   * {@link Advanced.deviceKeys}, which must hash to that ID, and its terms. Resolves to the roster
   * event's ID.
   */
  grantGuest(
    space: Space | SpaceId,
    member: MemberId,
    keys: DeviceKeys,
    terms: GuestTerms,
  ): Promise<string> {
    return callAsync(
      () => this.#raw().grantGuest(idOf(space), member, keys, terms) as Promise<string>,
    );
  }

  /**
   * Starts holding a space this device was granted directly, before it holds any of its events:
   * {@link Advanced.ingest} takes them.
   */
  async follow(space: SpaceId): Promise<Space> {
    return Space.wrap(
      await callAsync(() => this.#raw().follow(space) as Promise<raw.Space>),
      this.#device,
    );
  }

  /** The space's signed events this device holds, in canonical order. */
  signedEvents(space: Space | SpaceId): Promise<Uint8Array[]> {
    return callAsync(() => this.#raw().signedEvents(idOf(space)) as Promise<Uint8Array[]>);
  }

  /** Takes a space's signed events from another party. */
  ingest(space: Space | SpaceId, events: readonly Uint8Array[]): Promise<Ingested> {
    return callAsync(() => this.#raw().ingest(idOf(space), [...events]) as Promise<Ingested>);
  }

  /** How many of the device's changes in the space no peer has acknowledged yet. */
  outbox(space: Space | SpaceId): Promise<number> {
    return callAsync(() => this.#raw().outbox(idOf(space)) as Promise<number>);
  }
}

function idOf(space: Space | SpaceId): SpaceId {
  return typeof space === "string" ? space : space.id;
}

/**
 * The valid roster events (or device-list events) since the last checkpoint in effect at which the
 * device proposes the next one by default.
 */
export const PROPOSE_AT_ROSTER_EVENTS = 1024;

/**
 * The bytes of frame events since the last checkpoint in effect at which the device proposes the
 * next one by default: 4 MiB.
 */
export const PROPOSE_AT_FRAME_BYTES = 4 * 1024 * 1024;

/** What a device does about checkpoints by itself ({@link Device.setCheckpointPolicy}). */
export interface CheckpointPolicy {
  /**
   * Whether an administrator's device proposes a checkpoint by itself once the space's history
   * since the last one reaches a threshold, and whether a device proposes one of its person's
   * device list. With it off, the application proposes, if ever, by itself. Default `true`.
   */
  readonly propose: boolean;
  /** Whether the device forgets what came before a checkpoint once it is in effect. Default `true`. */
  readonly forget: boolean;
  /**
   * The valid roster events (or device-list events) since the last checkpoint in effect at which
   * the device proposes the next one: {@link PROPOSE_AT_ROSTER_EVENTS} by default.
   */
  readonly rosterEvents: number;
  /**
   * The bytes of frame events since the last checkpoint in effect at which the device proposes the
   * next one: {@link PROPOSE_AT_FRAME_BYTES} by default.
   */
  readonly frameBytes: number;
}

/** A checkpoint of this device's person's device list that waits for votes. */
export interface PendingListCheckpoint {
  readonly id: CheckpointId;
  /**
   * The person's devices it waits for: each must sign a list event after it. One that will not
   * return can be removed from the list ({@link Device.removeDevice}).
   */
  readonly waitingFor: MemberId[];
}

/** The checkpoints of this device's person's device list ({@link Device.listCheckpoints}). */
export interface ListCheckpointStatus {
  /** The list checkpoint in effect; `null` with none. */
  readonly inEffect: CheckpointId | null;
  /** The list checkpoints waiting for votes. */
  readonly pending: PendingListCheckpoint[];
  /** Whether this device forgot the list events before the checkpoint in effect. */
  readonly forgot: boolean;
  /** List checkpoints that rival the one this device kept: until it holds their past, the list's changes wait. */
  readonly rivals: CheckpointId[];
}

/** What a peer connection has done, for an application to show. */
export interface PeerStatus {
  /** Whether the connection runs. */
  readonly connected: boolean;
  /**
   * Whether it is connecting again because the peer asked it to, such as to move it to another of
   * its machines. That is no error: the connection goes on once connected.
   */
  readonly reconnecting: boolean;
  /** How many times it has connected again so. */
  readonly reconnects: number;
  /** Why it ended, once it has; `null` while it runs. */
  readonly closed: string | null;
  /** The spaces the peer keeps and syncs on this connection. */
  readonly spaces: SpaceId[];
  /**
   * Spaces the peer refused, with its reason code. A space refused `moved` was handed over to
   * another peer, and is no longer presented on this connection.
   */
  readonly refused: { space: SpaceId; code: string }[];
  /** How many of this device's changes the peer refused to keep; they are offered again. */
  readonly refusedChanges: number;
  /**
   * How many fetch keys the peer registered as recovery entries on this connection: a recovery
   * sheet reaches the spaces they serve through this peer.
   */
  readonly recoveryEntries: number;
  /**
   * Spaces in which the peer served less than this device knows of (`Withheld`), since the device
   * opened. The device fetches what it lacks from other replicas.
   */
  readonly withheld: SpaceId[];
  /**
   * Spaces in which the peer no longer held events it acknowledged (`RolledBack`), since the device
   * opened. This device's own events among them count as not durable again, and are offered again.
   */
  readonly rolledBack: SpaceId[];
}

/** A connection to an always-on peer. */
export class Peer extends Handle<raw.Peer> {
  private constructor(value: raw.Peer) {
    super(value, "Peer");
  }

  /** @internal */
  static wrap(value: raw.Peer): Peer {
    return new Peer(value);
  }

  /** The URL the device connected to. */
  get url(): string {
    return call(() => this.raw().url);
  }

  /** What the connection has done so far. */
  status(): PeerStatus {
    return call(() => this.raw().status() as PeerStatus);
  }

  /** Closes the connection. */
  close(): void {
    call(() => this.raw().close());
  }
}

/**
 * Something that happened on a device: a space changed, this device was removed from one, one
 * moved where it cannot follow, or a checkpoint of a space or of the person's device list needs
 * the application's attention.
 */
export type Event =
  | ChangedEvent
  | RemovedEvent
  | WriteReadyEvent
  | MovedEvent
  | PendingChangesEvent
  | DelayedEvent
  | DeliveredEvent
  | UndeliveredEvent
  | DepositPeerDistrustedEvent
  | WithheldEvent
  | RolledBackEvent
  | BadStatementEvent
  | CheckpointPendingEvent
  | CheckpointInEffectEvent
  | BadCheckpointEvent
  | LateEvent
  | MixedCutEvent
  | CheckpointRivalEvent
  | NeedsLaterVersionEvent
  | RequestSignedAgainEvent
  | ErasedWhileLateEvent
  | ErasureUnansweredEvent
  | PeerNeedsVersionEvent
  | PeerErrorEvent
  | SlotHeldEvent
  | ErasureCheckpointEvent
  | ErasureAwaitingWelcomeEvent
  | ErasureCannotEraseEvent
  | ErasureLateAtPeerEvent
  | ErasureVoidEvent
  | CheckpointWithheldEvent
  | RankAttemptRefusedEvent
  | BackdatedCheckpointEvent
  | ListCheckpointPendingEvent
  | ListCheckpointRivalEvent;

/**
 * A valid checkpoint of the space waits for votes: it takes effect once each administrator in
 * `waitingFor` has written anything after it. Reported when it appears, and again each time whom
 * it waits for changes; {@link Space.checkpoints} gives the current answer. Show whom it waits
 * for: an administrator that will not return can be removed by another administrator.
 */
export interface CheckpointPendingEvent {
  readonly kind: "checkpointPending";
  /** The space. */
  readonly space: SpaceId;
  /** The checkpoint. */
  readonly checkpoint: CheckpointId;
  /** The administrators it waits for. */
  readonly waitingFor: MemberId[];
}

/**
 * A checkpoint of the space took effect: nothing before it changes any verdict again, work made at
 * the same time as it is void, and this device may forget what came before it. Reported once per
 * checkpoint.
 */
export interface CheckpointInEffectEvent {
  readonly kind: "checkpointInEffect";
  /** The space. */
  readonly space: SpaceId;
  /** The checkpoint. */
  readonly checkpoint: CheckpointId;
}

/**
 * A checkpoint of the space is void (`BadCheckpoint`): its record or its predecessor is not that of
 * its past, or its record does not match it. It never takes effect. Reported once per checkpoint.
 */
export interface BadCheckpointEvent {
  readonly kind: "badCheckpoint";
  /** The space. */
  readonly space: SpaceId;
  /** The checkpoint. */
  readonly checkpoint: CheckpointId;
}

/**
 * Membership changes this device made at the same time as a checkpoint in effect are void
 * (`Late`), and the device does not make them again by itself: show them, and let the
 * administrator make each again if it still should. Late removals and demotions are signed again,
 * and late edits sent again, by the device itself. Reported each time the list changes;
 * {@link Space.lateChanges} gives it.
 */
export interface LateEvent {
  readonly kind: "late";
  /** The space. */
  readonly space: SpaceId;
  /** The changes. */
  readonly changes: LateChange[];
}

/**
 * An event of the space is void as `MixedCut`: it follows a checkpoint and cites an event that does
 * not. Reported once per event.
 */
export interface MixedCutEvent {
  readonly kind: "mixedCut";
  /** The space. */
  readonly space: SpaceId;
  /** The event, as 64 hex digits. */
  readonly event: string;
}

/**
 * A checkpoint of the space rivals the one this device kept when it forgot what came before it:
 * two groups of administrators each made one at the same time. Until the device has fetched the
 * rival's past from a member or peer that kept it, every change of the space waits; it fetches it
 * by itself. Reported once per checkpoint.
 */
export interface CheckpointRivalEvent {
  readonly kind: "checkpointRival";
  /** The space. */
  readonly space: SpaceId;
  /** The rival checkpoint. */
  readonly checkpoint: CheckpointId;
}

/**
 * The space needs a later version of Frasil than this build: its descriptor, a checkpoint's
 * record or a roster event uses a hook a later document defines. The device holds what uses it,
 * and everything after, and signs nothing more in the space: each write there fails with
 * `needs_later_version`. Ask the person to update the app. Reported once per space.
 */
export interface NeedsLaterVersionEvent {
  readonly kind: "needsLaterVersion";
  /** The space. */
  readonly space: SpaceId;
}

/**
 * A request of this device's that a checkpoint made late (an erasure, or a release or restore of a
 * document) was signed again after the checkpoint: the late one counts for nothing. Reported once
 * per request.
 */
export interface RequestSignedAgainEvent {
  readonly kind: "requestSignedAgain";
  /** The space. */
  readonly space: SpaceId;
  /** The late request. */
  readonly request: string;
}

/**
 * A peer erased the space, though this device's view holds the erasure late under a checkpoint that
 * kept the space: the peer carried it out before the checkpoint's cut reached it. The space is gone
 * from that peer for good: move it to another peer, or give it up.
 */
export interface ErasedWhileLateEvent {
  readonly kind: "erasedWhileLate";
  /** The space. */
  readonly space: SpaceId;
  /** The device that asked for the erasure, when this device knows it. */
  readonly by: MemberId | null;
}

/**
 * This device dropped the space for its own erasure, and past the bound, the erasure timeout at its
 * default from the erasure's first sight, these peers have not answered that they erased it: the
 * space may live on there. The device keeps asking until each answers, or the application gives
 * the space up with {@link Device.giveUpSpace}.
 */
export interface ErasureUnansweredEvent {
  readonly kind: "erasureUnanswered";
  /** The space. */
  readonly space: SpaceId;
  /** The peers, by address, that have not answered. */
  readonly peers: readonly string[];
}

/**
 * A peer served, instead of answering that it erased the space, a checkpoint that makes this
 * device's erasure late: the space lives on there. The device fetches the space again, to erase it
 * again after the checkpoint or to report the erasure void; the application may give it up instead.
 */
export interface ErasureLateAtPeerEvent {
  readonly kind: "erasureLateAtPeer";
  /** The space. */
  readonly space: SpaceId;
  /** The peer, by address. */
  readonly peer: string;
}

/**
 * After a checkpoint made this device's erasure late, the device no longer administers the space:
 * the erasure is void, and the space lives on.
 */
export interface ErasureVoidEvent {
  readonly kind: "erasureVoid";
  /** The space. */
  readonly space: SpaceId;
}

/**
 * A checkpoint of the space is contested for this device: it hears the device, or the device's view
 * lowers its author or an administrator it keeps by a concurrent event of a member that outranks
 * them. The device writes nothing that builds on it. Show it as a duel, with who proposed it and the
 * lowering events on both sides. Reported once per checkpoint.
 */
export interface CheckpointWithheldEvent {
  readonly kind: "checkpointWithheld";
  /** The space. */
  readonly space: SpaceId;
  /** The checkpoint. */
  readonly checkpoint: CheckpointId;
  /** Who proposed it. */
  readonly proposedBy: MemberId;
  /** The roster events of its past that lower administrators. */
  readonly theirs: string[];
  /** The roster events of this device's view, concurrent with it, that lower its author or an administrator it keeps. */
  readonly ours: string[];
}

/**
 * A roster event of the space is void because its author acted on an administrator of a higher
 * rank, or granted a rank above its own. Not a duel: list it apart. Reported once per event.
 */
export interface RankAttemptRefusedEvent {
  readonly kind: "rankAttemptRefused";
  /** The space. */
  readonly space: SpaceId;
  /** The void roster event. */
  readonly event: string;
  /** Its author. */
  readonly author: MemberId;
}

/**
 * A checkpoint of the space was proposed by an administrator that a removal made at the same time
 * removes. Reported to administrators, once per checkpoint and removal.
 */
export interface BackdatedCheckpointEvent {
  readonly kind: "backdatedCheckpoint";
  /** The space. */
  readonly space: SpaceId;
  /** The checkpoint. */
  readonly checkpoint: CheckpointId;
  /** The removal, as 64 hex digits. */
  readonly removal: string;
}

/**
 * A checkpoint of this device's person's device list waits for votes: it takes effect once each
 * device in `waitingFor` has signed a list event after it. Reported when it appears, and again each
 * time whom it waits for changes; {@link Device.listCheckpoints} gives the current answer.
 */
export interface ListCheckpointPendingEvent {
  readonly kind: "listCheckpointPending";
  /** The list checkpoint. */
  readonly checkpoint: CheckpointId;
  /** The devices it waits for. */
  readonly waitingFor: MemberId[];
}

/**
 * A checkpoint of this device's person's device list rivals the one this device kept when it
 * forgot the list's earlier events: until the device holds its past, the list's changes wait.
 * Reported once per checkpoint.
 */
export interface ListCheckpointRivalEvent {
  readonly kind: "listCheckpointRival";
  /** The rival list checkpoint. */
  readonly checkpoint: CheckpointId;
}

/**
 * A peer served less of a space than this device knows of (`Withheld`): it left out units a
 * stream's listing should name, events of a state it served before, or a member's head statement's
 * heads that the member then supplied, when the peer had acknowledged them or still lacked them
 * five minutes after it first answered that it did not hold them. The device fetches what it lacks
 * from other replicas; {@link Peer.status} says which peer.
 */
export interface WithheldEvent {
  readonly kind: "withheld";
  /** The space. */
  readonly space: SpaceId;
}

/**
 * A peer, or in a space with no always-on peer the member `member`, no longer holds events it
 * acknowledged (`RolledBack`). This device's own events among them count as not durable again:
 * they are back among the changes awaiting durability (a {@link PendingChangesEvent} follows), and
 * are offered again on every connection.
 */
export interface RolledBackEvent {
  readonly kind: "rolledBack";
  /** The space. */
  readonly space: SpaceId;
  /** The member, when a member acknowledged; `null` for a peer. */
  readonly member: MemberId | null;
}

/**
 * A member's head statement named events that member could not supply when asked
 * (`BadStatement`): the statement is dropped.
 */
export interface BadStatementEvent {
  readonly kind: "badStatement";
  /** The space. */
  readonly space: SpaceId;
  /** The member that made it. */
  readonly member: MemberId;
}

/** How many deposit tokens a device holds for a peer, and whether it draws there. */
export interface DepositTokens {
  /** The unspent tokens of the peer's live keys. */
  readonly held: number;
  /** The peer answered a draw `allowance_exhausted` less than 24 hours ago: no draw meanwhile. */
  readonly paused: boolean;
  /** The peer's key lists contradicted one another: no draw or spend until trusted again. */
  readonly distrusted: boolean;
  /** A grant is held that no draw used yet. */
  readonly grant: boolean;
}

/**
 * A deposit in a device mailbox, such as a welcome, was not accepted: the peer answered `busy` or
 * `rate_limited`, or was not reached. The device keeps it and sends it again by itself, after a
 * random wait that grows to an hour, for up to 30 days. Reported at each attempt that fails.
 */
export interface DelayedEvent {
  readonly kind: "delayed";
  /** The peer's origin. */
  readonly peer: string;
  /** The peer's reason code, or why it was not reached. */
  readonly reason: string;
}

/** A deposit reported {@link DelayedEvent} was accepted. */
export interface DeliveredEvent {
  readonly kind: "delivered";
  /** The peer's origin. */
  readonly peer: string;
}

/** A deposit was given up: 30 days passed (`expired`), or the peer refused it for good. */
export interface UndeliveredEvent {
  readonly kind: "undelivered";
  /** The peer's origin. */
  readonly peer: string;
  /** `expired`, or the peer's reason code. */
  readonly reason: string;
}

/**
 * The device stopped drawing and spending deposit tokens at a peer: its key lists contradict one
 * another (`key_inconsistent`), until {@link Device.trustDepositKeys}, or a batch's proof did not
 * hold (`bad_proof`), which drops that batch. Deposits there go on without tokens.
 */
export interface DepositPeerDistrustedEvent {
  readonly kind: "depositPeerDistrusted";
  /** The peer's origin. */
  readonly peer: string;
  /** `key_inconsistent` or `bad_proof`. */
  readonly reason: string;
}

/** An observed outbox count changed; rapid changes may coalesce. */
export interface PendingChangesEvent {
  readonly kind: "pendingChanges";
  readonly space: SpaceId;
  readonly count: bigint;
}

/** A space changed. */
export interface ChangedEvent {
  readonly kind: "changed";
  /** The space: this device wrote there, or received changes from a member or a peer. */
  readonly space: SpaceId;
  /** The streams whose content changed. */
  readonly streams: string[];
  /** Whether its members or their levels may have changed. */
  readonly members: boolean;
}

/**
 * This device is no longer a member of the space: it holds the event that removes it, or removes
 * its person, and the space's roster resolves without it. {@link Space.level} is now `undefined`
 * and {@link Space.members} no longer lists it. It reads nothing written after the removal.
 * Reported once per removal.
 */
export interface RemovedEvent {
  readonly kind: "removed";
  /** The space. */
  readonly space: SpaceId;
}

/**
 * This device, opened as restored, has synced the space and may write there again: until now each
 * write there rejected with `sync_before_writing`. Reported once per space while the device is
 * open, and never for a space the device could already write in; {@link Space.isWriteReady} gives
 * the current answer.
 */
export interface WriteReadyEvent {
  readonly kind: "writeReady";
  /** The space. */
  readonly space: SpaceId;
}

/**
 * A peer answered that it handed the space over to another peer, and every peer this device
 * knows for the space answered that it does not host it: its home peer and its peer hints.
 * Reported once, until a peer grants the space again. For a library the person's account holds,
 * ask its issuer for the library's home peer and give it to {@link Space.setHomePeer}; the
 * device then syncs there.
 */
export interface MovedEvent {
  readonly kind: "moved";
  /** The space. */
  readonly space: SpaceId;
}

/**
 * A device's events, from the moment they were asked for: `await events.next()`, or
 * `for await (const event of events)`. Each holder receives every event; one that falls far
 * behind skips the oldest. {@link Events.close} ends it.
 */
export class Events extends Handle<raw.Events> implements AsyncIterable<Event> {
  #waiting: Promise<unknown> = Promise.resolve();

  private constructor(value: raw.Events) {
    super(value, "Events");
  }

  /** @internal */
  static wrap(value: raw.Events): Events {
    return new Events(value);
  }

  /** The next event; `undefined` once closed. Calls wait their turn. */
  next(): Promise<Event | undefined> {
    const next = this.#waiting.then(async () => {
      for (;;) {
        if (this.isDisposed) return undefined;
        const event = await callAsync(
          () => this.raw().next() as Promise<Event | { kind: "other" } | undefined>,
        );
        if (this.isDisposed || event === undefined) return undefined;
        if (event.kind !== "other") {
          return event;
        }
      }
    });
    this.#waiting = next.catch(() => {});
    return next;
  }

  async *[Symbol.asyncIterator](): AsyncIterator<Event> {
    for (;;) {
      const event = await this.next();
      if (event === undefined) return;
      yield event;
    }
  }

  /** Stops the events. A `next()` waiting resolves `undefined` at the next event. */
  close(): void {
    this.free();
  }
}

/** Progress of one independent space admission; callback errors do not cancel the batch. */
export interface SpaceAdmission {
  readonly space: SpaceId;
  /** Grant committed (sender), or verified against the roster (receiver). */
  readonly granted: boolean;
  /** Undefined on success. Delivery failure can follow a committed grant; retry is safe. */
  readonly error?: Readonly<Pick<FrasilError, "code" | "message" | "class" | "whatToDo">>;
}

/** Evidence a residue can check without space keys. */
export interface ErasureCheckpointEvent {
  readonly kind: "erasureCheckpoint";
  readonly space: SpaceId;
  readonly peer: string;
  readonly checkpoint: CheckpointId;
  readonly standing: 0 | 1 | 2;
}
/** A welcome has been requested from the saved administrators. */
export interface ErasureAwaitingWelcomeEvent {
  readonly kind: "erasureAwaitingWelcome";
  readonly space: SpaceId;
}
/** The peer says the device's administrator slot is absent. */
export interface ErasureCannotEraseEvent {
  readonly kind: "erasureCannotErase";
  readonly space: SpaceId;
  readonly peer: string;
}

/** The peer contradicted the signed evidence in its untrusted answer. */
export interface PeerErrorEvent {
  readonly kind: "peerError";
  readonly space: SpaceId;
  readonly peer: string;
  readonly answer: Uint8Array;
}

/** Another pseudonym holds this device's administrator slot. */
export interface SlotHeldEvent {
  kind: "slotHeld";
  space: SpaceId;
  holding: string;
  holder: "another installation of this device" | "another device" | "unknown";
  erasureWaiting: boolean;
  peer: string | null;
}

/** This peer needs a later version to follow the space checkpoints. */
export interface PeerNeedsVersionEvent {
  readonly kind: "peerNeedsVersion";
  readonly space: SpaceId;
  readonly peer: string;
}
