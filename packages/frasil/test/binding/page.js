// @ts-nocheck: served to the page as it is, where `/dist/index.js` is the built package;
// `harness.ts` types what the scenarios call.
// The scenarios' page: it loads the built package and hands it, with a few helpers, to the
// scenarios, which drive it with `page.evaluate`. `window.ready` resolves once the package is
// loaded.
import * as frasil from "/dist/index.js";

/** Bytes as lowercase hex, to carry keys between pages. */
function hex(bytes) {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

/** Hex as bytes. */
function bytes(text) {
  const out = new Uint8Array(text.length / 2);
  for (let index = 0; index < out.length; index += 1) {
    out[index] = Number.parseInt(text.slice(2 * index, 2 * index + 2), 16);
  }
  return out;
}

/** SHA-256 of bytes, as hex. */
async function digest(data) {
  return hex(new Uint8Array(await crypto.subtle.digest("SHA-256", data)));
}

/** Waits until `check()` resolves truthy, polling, or fails after `deadline` milliseconds. */
async function until(check, what, deadline = 30_000) {
  const started = Date.now();
  for (;;) {
    const value = await check();
    if (value) return value;
    if (Date.now() - started > deadline) throw new Error(`timed out waiting for ${what}`);
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
}

/** `undefined` for a stream this device holds no change of yet; the value otherwise. */
async function unlessUnknown(body) {
  try {
    return await body();
  } catch (error) {
    if (error.code === "unknown_stream") return undefined;
    throw error;
  }
}

/** The text container the scenarios write. */
const BODY = "body";

/**
 * One device in this page, kept in IndexedDB under `name`, which keeps its sealed keys beside its
 * records. Its unlock key is kept in `localStorage` so a reload can open it again: a test's
 * shortcut, where an application would take the unlock key from a passkey or the platform's
 * keychain.
 */
const agent = {
  device: undefined,
  peer: undefined,
  /** Documents this page created, which exist in their space from their first edit. */
  made: new Map(),
  /**
   * The `expiresAt` of the invitation a `"wait-then-accept"` import holds, once it is shown, so
   * that a test can move this page's wall clock past it.
   */
  waitingUntil: undefined,
  /** The spaces of the events the device told, in order. */
  told: [],

  async create(name) {
    const unlockKey = crypto.getRandomValues(new Uint8Array(32));
    localStorage.setItem(name, hex(unlockKey));
    this.device = await frasil.Device.open(frasil.Storage.indexedDb(name), unlockKey);
    this.watch();
    return {
      id: this.device.id,
      keys: hex(this.device.advanced.deviceKeys()),
    };
  },

  async open(name) {
    const kept = localStorage.getItem(name);
    if (!kept) throw new Error(`no device ${name} in this origin`);
    this.device = await frasil.Device.open(frasil.Storage.indexedDb(name), bytes(kept));
    this.watch();
    return { id: this.device.id, continuity: await this.device.advanced.continuity() };
  },

  /**
   * Makes a person of the device made as `name`, its keys sealed again under the same unlock key.
   * Resolves to `{ person, personalSpace }`.
   */
  async makePerson(name) {
    return this.device.advanced.makePerson(bytes(localStorage.getItem(name)));
  },

  /** Adds a recovery key, and resolves to its sheet's text. */
  async createRecoverySheet() {
    return (await this.device.createRecoverySheet()).text;
  },

  /** Waits until the peer connection registered `count` recovery entries. */
  async registered(count) {
    await until(() => this.peer.status().recoveryEntries >= count, "the recovery entries");
  },

  /**
   * Makes a new device, kept as `name`, of the person a recovery sheet names, through the peer.
   * Resolves to its ID.
   */
  async recover(name, sheet) {
    const unlockKey = crypto.getRandomValues(new Uint8Array(32));
    localStorage.setItem(name, hex(unlockKey));
    this.device = await frasil.Device.recover(
      frasil.Storage.indexedDb(name),
      unlockKey,
      sheet,
      location.origin,
    );
    this.watch();
    return this.device.id;
  },

  /** The code `recover` rejects with, or `null` when it succeeds. */
  async recoverCode(name, sheet) {
    try {
      await this.recover(name, sheet);
      return null;
    } catch (error) {
      return error.code;
    }
  },

  /** Records the space of every event the device tells. */
  async watch() {
    for await (const event of this.device.events()) this.told.push(event.space);
  },

  async createSpace() {
    return (await this.device.createSpace()).id;
  },

  async spaces() {
    return (await this.device.spaces()).map((space) => space.id);
  },

  /** Grants a device the space at `level`, `write` unless given. */
  async grant(space, id, keys, level = "write") {
    return this.device.advanced.grantDevice(space, id, bytes(keys), level, "with-history");
  },

  async grantGuest(space, id, keys, session) {
    return this.device.advanced.grantGuest(space, id, bytes(keys), {
      level: "write",
      session: bytes(session),
      // Handed over directly, with no snapshot: the guest takes the space's earlier keys.
      history: "with-history",
    });
  },

  async leave(space) {
    await (await this.device.space(space)).leave();
  },

  /** The code an edit rejects with, or `null` when it succeeds. */
  async editCode(space, id, insert) {
    try {
      await this.edit(space, id, 0, 0, insert);
      return null;
    } catch (error) {
      return error.code;
    }
  },

  /** Waits until the space's members no longer name `id`. */
  async waitRemoved(space, id) {
    await until(
      async () => !(await this.members(space)).some((member) => member.startsWith(`${id}:`)),
      `${id} to be removed`,
    );
  },

  async signedEvents(space) {
    return (await this.device.advanced.signedEvents(space)).map(hex);
  },

  async follow(space) {
    return (await this.device.advanced.follow(space)).id;
  },

  async ingest(space, events) {
    return this.device.advanced.ingest(space, events.map(bytes));
  },

  async level(space) {
    return (await this.device.space(space)).level();
  },

  /** Waits until this device's level in the space is `level`. */
  async waitLevel(space, level) {
    await until(async () => (await this.level(space)) === level, `the level ${level}`);
  },

  async setLevel(space, member, level) {
    const opened = await this.device.space(space);
    // An administrator is made at a rank: the top one in these scenarios.
    if (level === "administer") await opened.raise(member, 255);
    else await opened.setLevel(member, level);
  },

  /** Sends what the space holds of this device's and waits until a peer holds it. */
  async flush(space) {
    await (await this.device.space(space)).flush();
  },

  async setHomePeer(space, url) {
    await (await this.device.space(space)).setHomePeer(url);
  },

  async knownPeers(space) {
    return (await this.device.space(space)).knownPeers();
  },

  async members(space) {
    return (await (await this.device.space(space)).members()).map((m) => `${m.id}:${m.level}`);
  },

  async createDocument(space) {
    const doc = (await this.device.space(space)).createDocument();
    this.made.set(doc.id, doc);
    return doc.id;
  },

  async document(space, id) {
    return this.made.get(id) ?? (await this.device.space(space)).document(id);
  },

  async documents(space) {
    const streams = await (await this.device.space(space)).streams();
    return streams.filter((stream) => stream.kind === "document").map((stream) => stream.id);
  },

  async edit(space, id, index, deleteCount, insert) {
    const doc = await this.document(space, id);
    await doc.edit((edit) => {
      const text = edit.text(BODY);
      if (deleteCount > 0) text.delete(index, deleteCount);
      if (insert) text.insert(index, insert);
    });
  },

  async text(space, id) {
    return unlessUnknown(async () => (await this.document(space, id)).text(BODY));
  },

  /** The document's history, as the package returns it. */
  async history(space, id) {
    return (await this.document(space, id)).history();
  },

  /** The size of the document's snapshot at a version, and its SHA-256: a page has no Loro. */
  async documentAt(space, id, version) {
    const snapshot = await (await this.document(space, id)).at(version);
    return { size: snapshot.length, digest: await digest(snapshot) };
  },

  async createRecords(space) {
    const records = (await this.device.space(space)).createRecords();
    this.made.set(records.id, records);
    return records.id;
  },

  async records(space, id) {
    return this.made.get(id) ?? (await this.device.space(space)).records(id);
  },

  /** Writes one cell, inserting the row when `insert`. */
  async writeCell(space, id, table, key, column, value, insert) {
    const records = await this.records(space, id);
    await records.write((tx) => {
      if (insert) tx.insert(table, key);
      tx.set(table, key, column, value);
    });
  },

  /** Waits until a row's cell shows `value`. */
  async waitCell(space, id, table, key, column, value) {
    await until(async () => {
      const records = await unlessUnknown(() => this.records(space, id));
      const row = records && (await records.row(table, key));
      return row?.[column] === value;
    }, `${table}/${key} ${column} = ${value}`);
  },

  /** The tables' history, as the package returns it. */
  async recordsHistory(space, id) {
    return (await this.records(space, id)).history();
  },

  /** One row of a table as it stood after a change. */
  async recordsAt(space, id, change, table, key) {
    const tables = await (await this.records(space, id)).at(change);
    return tables.get(table)?.get(key);
  },

  async tag(space, doc, name) {
    return (await this.document(space, doc)).tag(name);
  },

  async recordsTag(space, id, name) {
    return (await this.records(space, id)).tag(name);
  },

  async versions(space) {
    return (await this.device.space(space)).versions();
  },

  async untag(space, id) {
    await (await this.device.space(space)).untag(id);
  },

  async versionsStream(space) {
    return (await this.device.space(space)).versionsStream;
  },

  /** Suggests one cell, and resolves to the suggestion's ID. */
  async suggestCell(space, id, table, key, column, value) {
    const records = await this.records(space, id);
    await records.suggest((tx) => tx.set(table, key, column, value));
    const open = await records.suggestions();
    return open[open.length - 1].id;
  },

  async recordsReview(space, id, suggestion) {
    return (await this.records(space, id)).review(suggestion);
  },

  async recordsAccept(space, id, suggestion) {
    await (await this.records(space, id)).accept([suggestion]);
  },

  /**
   * Puts a blob of `size` bytes, each from its index, in a new blob stream: from memory, or with
   * `fromFile` from a `Blob` read a chunk at a time. Resolves to the stream's ID, the blob's, and
   * its SHA-256, to compare in another page.
   */
  async putBlob(space, size, fromFile = false) {
    const data = new Uint8Array(size);
    for (let index = 0; index < size; index += 1) data[index] = (index * 31 + 7) & 0xff;
    const blobs = (await this.device.space(space)).createBlobs();
    const blob = fromFile
      ? await blobs.putFile("pattern.bin", new Blob([data]))
      : await blobs.put(data, { name: "pattern.bin" });
    return { stream: blobs.id, blob, digest: await digest(data) };
  },

  /**
   * Exports `space` to a space file under `kind`, as hex. `options` are the package's, with the
   * seal as hex.
   */
  async exportSpaceFile(space, kind, options = {}) {
    const { seal, ...rest } = options;
    const file = await (await this.device.space(space)).exportSpaceFile(
      kind,
      seal ? { ...rest, seal: bytes(seal) } : rest,
    );
    return hex(file);
  },

  /** Appends what this device holds of `space` to a file given as hex: the grown file, as hex. */
  async appendSpaceFile(space, file) {
    return hex(await (await this.device.space(space)).appendSpaceFile(bytes(file)));
  },

  /**
   * Imports a space file given as hex, of `kind`, with the file key as hex if any: the road in
   * and the space, or the refusal's code. An invitation is shown (its inviter, level and label)
   * and then accepted or declined as `decision` says, `"accept"` or `"decline"`.
   */
  async importSpaceFile(file, kind, key, decision = "accept") {
    try {
      const imported = await this.device.importSpaceFile(
        bytes(file),
        kind,
        key ? { key: bytes(key) } : {},
      );
      if (imported.road !== "invited") return { road: imported.road, space: imported.space.id };
      const { invitation } = imported;
      const shown = {
        road: "invited",
        inviter: invitation.inviter,
        level: invitation.level,
        label: invitation.label ?? null,
        space: invitation.space,
      };
      if (decision === "decline") {
        await invitation.decline();
        return { ...shown, declined: true };
      }
      if (decision === "wait-then-accept") {
        // Past the invite's expiry: the acceptance is refused, and the
        // invitation is still in hand to decline. The claimant's wall clock
        // counts whole seconds and admits `now_wall <= expires_at`
        // (overview.md, 6.6 Instants exchanged between parties), so the
        // wait runs until the second after `expires_at` has begun. It reads
        // the clock often, so a test that sets the page's clock ends it.
        const past = (invitation.expiresAt + 1) * 1000;
        this.waitingUntil = invitation.expiresAt;
        while (Date.now() < past) {
          await new Promise((resolve) => setTimeout(resolve, Math.min(past - Date.now(), 100)));
        }
        this.waitingUntil = undefined;
        try {
          const space = await invitation.accept();
          return { ...shown, accepted: space.id };
        } catch (error) {
          await invitation.decline();
          return { ...shown, acceptCode: error.code, declined: true };
        }
      }
      const space = await invitation.accept();
      return { ...shown, accepted: space.id };
    } catch (error) {
      return { code: error.code };
    }
  },

  /** What a space file given as hex says of itself. */
  sniffSpaceFile(file) {
    return frasil.Device.sniffSpaceFile(bytes(file));
  },

  /** A blob's SHA-256, once the device holds it whole; `null` before. */
  async blobDigest(space, stream, blob) {
    const data = await unlessUnknown(async () =>
      (await (await this.device.space(space)).blobs(stream)).get(blob),
    );
    return data === undefined ? null : digest(data);
  },

  /**
   * Starts joining through the exchange mailbox at the test origin's peer, as `name`. Resolves to
   * the text an administrator enters; the six digits this device shows are kept in `joinCode`,
   * and the person confirms them at once.
   */
  async joinViaPeer(name, delay = 0) {
    this.joining = await this.device.joinViaPeer(location.origin, name, async (code) => {
      this.joinCode = code;
      await new Promise((resolve) => setTimeout(resolve, delay));
      return true;
    });
    return this.joining.text;
  },

  /**
   * Starts joining the person of another device through the exchange mailbox at the test origin's
   * peer, as `name`, with the unlock key the device made as `kept` was opened with. Resolves to the
   * text the other device enters; the six digits shown are kept in `joinCode`.
   */
  async joinPersonViaPeer(kept, person, name) {
    const unlockKey = bytes(localStorage.getItem(kept));
    this.joiningPerson = await this.device.joinPersonViaPeer(
      location.origin,
      person,
      name,
      unlockKey,
      async (code) => {
        this.joinCode = code;
        return true;
      },
    );
    return this.joiningPerson.text;
  },

  /** Waits until the device is the person's. Resolves to the IDs of the spaces it reached. */
  async joinedPerson() {
    return (await this.joiningPerson.joined()).map((space) => space.id).sort();
  },

  /** Adds the device whose `text` is entered to this device's person. Resolves to the six digits. */
  async admitDevice(text) {
    let shown;
    await this.device.admitDevice(text, "the person's browser", async (code) => {
      shown = code;
      return true;
    });
    return shown;
  },

  /** The device's person, or `null`. */
  async person() {
    return this.device.person();
  },

  async personalSpace() {
    return this.device.personalSpace();
  },

  /** Waits until the device joined through the mailbox. Resolves to the space's ID. */
  async joined() {
    return (await this.joining.joined()).id;
  },

  /** Admits the device whose `text` is entered, at `level`. Resolves to the six digits shown. */
  async admit(space, text, level) {
    let shown;
    await (await this.device.space(space)).admit(
      text,
      level,
      "the admitting browser",
      async (code) => {
        shown = code;
        return true;
      },
    );
    return shown;
  },

  async outbox(space) {
    return this.device.advanced.outbox(space);
  },

  async connect() {
    this.peer = await this.device.connect(location.origin);
  },

  /** Goes offline: closes the peer connection. */
  disconnect() {
    this.peer?.close();
  },

  async close() {
    await this.device.close();
  },

  status() {
    return this.peer.status();
  },

  /** Waits until every change of the space this device made is durable. */
  async durable(space) {
    const held = await this.device.space(space);
    await until(() => held.isDurable(), "the space to be durable");
  },

  /**
   * The membership calls on this device, made a person, with no peer: whether its list delivery
   * is CBOR bytes (a map of two), whether it can suggest in a space it made, and the codes that
   * removing itself and revoking a text that is no link reject with.
   */
  async membershipCalls(name) {
    await this.makePerson(name);
    const delivery = await this.device.listDelivery();
    const space = await this.device.createSpace();
    const code = async (call) => {
      try {
        await call();
        return null;
      } catch (error) {
        return error.code;
      }
    };
    return {
      delivery: delivery instanceof Uint8Array && delivery[0] === 0xa2,
      canSuggest: await space.canSuggest(),
      removeSelf: await code(() => this.device.removeDevice(this.device.id)),
      revoke: await code(() => space.revokeInviteLink("not a link")),
    };
  },

  /**
   * Erases the space at its peers, over an administration connection of the page's own, and from
   * this device. Resolves to the spaces the device still holds.
   */
  async erase(space) {
    await (await this.device.space(space)).erase();
    return this.spaces();
  },

  /** Waits until the peer connection refused the space, and resolves to the peer's code. */
  async refusedCode(space) {
    return until(
      () => this.peer.status().refused.find((refusal) => refusal.space === space)?.code,
      "the peer to refuse the space",
    );
  },

  /** Waits until the document's text is `expected`. */
  async waitText(space, doc, expected) {
    await until(
      async () => (await this.text(space, doc)) === expected,
      `the text ${JSON.stringify(expected)}`,
    );
  },
};

window.frasil = frasil;
window.agent = agent;
window.helpers = { hex, bytes, until };
window.ready = Promise.resolve(true);
