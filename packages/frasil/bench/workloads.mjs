// The workloads of the WebAssembly benchmark (`scripts/bench-wasm.sh`), run against a built
// package in Node.js and in Chromium. Everything is offline and in memory: devices over
// `Storage.memory()`, no peer. Each workload has an untimed `once` (shared set-up), an untimed
// `prepare` per run, and the timed `go` it returns.
//
// What each measures, and which part of the module it exercises:
//
// - open device: key generation for both signature schemes, the key wrap and the store.
// - import a large document: reading a space file whose one document holds ~400 KB of text in 200
//   changes: verifying the signed changes and merging them into the Loro document.
// - merge into a held space: the same device holding the space already takes the file grown by
//   100 more changes.
// - apply small updates: 500 one-character edits, each a Loro change that is sealed and signed
//   (scheme 0) and applied.
// - import small updates: a file of 600 one-character changes, verified (scheme 0) and applied.
// - sign roster events: a space's administrator grants 100 devices, each a roster event signed
//   under scheme 2.
// - a membership change and a refresh in a space of 20 or 100 writers, with no checkpoint and
//   with one in effect: one grant signed, and one edit committed, each of which judges the view
//   again; and one edit in a space of 20 writers after 1,000 edits, with no checkpoint and with
//   one in effect before the edits.
// - verify and resolve a roster: a device that holds none of a space's events takes ~300 roster
//   events (grants and level changes, scheme 2) and resolves the members. The level changes raise
//   each member to `administer` and lower it to `write` again, neither of which rotates the
//   space's keys: an administrator that signs many rotations in a row, each wrapped to a hundred
//   members, takes far longer to set up than the benchmark is worth.

const BODY = "body";

/** @param {number} n */
const text = (n) => "lorem ipsum dolor sit amet ".repeat(Math.ceil(n / 27)).slice(0, n);

const key = () => crypto.getRandomValues(new Uint8Array(32));

/** @param {any} frasil */
const memoryDevice = (frasil) => frasil.Device.open(frasil.Storage.memory(), key());

/**
 * @param {any} frasil
 * @param {{ runs: number }} options
 */
export function workloads(frasil, { runs }) {
  /** Devices to close at the end. */
  const open = [];
  const device = async () => {
    const made = await memoryDevice(frasil);
    open.push(made);
    return made;
  };

  /** A space of kind `bench` with one document, edited `count` times with `insert` bytes each. */
  async function filled(count, insert) {
    const author = await device();
    const space = await author.createSpaceOfKind("bench");
    const doc = space.createDocument();
    let at = 0;
    for (let index = 0; index < count; index += 1) {
      const start = at;
      await doc.edit((edit) => edit.text(BODY).insert(start, text(insert)));
      at += insert;
    }
    return { author, space, doc, at };
  }

  /** Roster events: `helpers` devices, and an administrator that grants all of them. */
  async function roster(helpers) {
    const members = [];
    for (let index = 0; index < helpers; index += 1) {
      const made = await device();
      members.push({ device: made, id: made.id, keys: made.advanced.deviceKeys() });
    }
    const admin = await device();
    const space = await admin.createSpaceOfKind("bench");
    return { admin, space, members };
  }

  return [
    {
      name: "open a device",
      prepare: async () => async () => {
        const made = await memoryDevice(frasil);
        await made.close();
      },
    },
    {
      name: "import a large document",
      once: async () => {
        const { space } = await filled(200, 2048);
        return { file: await space.exportSpaceFile("bench") };
      },
      prepare: async ({ file }) => {
        const reader = await device();
        return async () => {
          await reader.importSpaceFile(file, "bench");
        };
      },
    },
    {
      name: "merge into a held space",
      once: async () => {
        const { space } = await filled(200, 2048);
        const first = await space.exportSpaceFile("bench");
        const doc = space.createDocument();
        for (let index = 0; index < 100; index += 1) {
          await doc.edit((edit) => edit.text(BODY).insert(index * 2048, text(2048)));
        }
        return { first, grown: await space.appendSpaceFile(first) };
      },
      prepare: async ({ first, grown }) => {
        const reader = await device();
        await reader.importSpaceFile(first, "bench");
        return async () => {
          await reader.importSpaceFile(grown, "bench");
        };
      },
    },
    {
      name: "apply 500 small updates",
      prepare: async () => {
        const author = await device();
        const doc = (await author.createSpaceOfKind("bench")).createDocument();
        return async () => {
          for (let index = 0; index < 500; index += 1) {
            await doc.edit((edit) => edit.text(BODY).insert(index, "x"));
          }
        };
      },
    },
    {
      name: "import 600 small updates",
      once: async () => {
        const { space } = await filled(600, 1);
        return { file: await space.exportSpaceFile("bench") };
      },
      prepare: async ({ file }) => {
        const reader = await device();
        return async () => {
          await reader.importSpaceFile(file, "bench");
        };
      },
    },
    {
      name: "sign 100 roster events (scheme 2)",
      once: async () => ({ members: (await roster(100)).members }),
      prepare: async ({ members }) => {
        const admin = await device();
        const space = await admin.createSpaceOfKind("bench");
        return async () => {
          for (const member of members) {
            await admin.advanced.grantDevice(space, member.id, member.keys, "write");
          }
        };
      },
    },
    {
      name: "verify and resolve ~300 roster events",
      once: async () => {
        // A device for each run besides the warm-up, all in the roster, each used once.
        const { admin, space, members } = await roster(runs + 2);
        for (const member of members) {
          await admin.advanced.grantDevice(space, member.id, member.keys, "write");
        }
        // Two more level changes of each, which rotate nothing: 3 events a device, 300 at 100
        // devices.
        const extra = Math.max(0, 100 - members.length);
        for (let index = 0; index < extra; index += 1) {
          const made = await device();
          await admin.advanced.grantDevice(space, made.id, made.advanced.deviceKeys(), "write");
          members.push({ device: made, id: made.id, keys: made.advanced.deviceKeys() });
        }
        for (const member of members) await space.raise(member.id, 255);
        for (const member of members) await space.setLevel(member.id, "write");
        return {
          space: space.id,
          events: await admin.advanced.signedEvents(space),
          readers: members.slice(0, runs + 2).map((member) => member.device),
          used: 0,
        };
      },
      prepare: async (shared) => {
        const reader = shared.readers[shared.used];
        shared.used += 1;
        if (reader === undefined) throw new Error("no unused device left for this run");
        const space = await reader.advanced.follow(shared.space);
        return async () => {
          const ingested = await reader.advanced.ingest(space, shared.events);
          if (ingested.refused?.length) {
            throw new Error(`ingest refused ${ingested.refused.length} events`);
          }
          await space.members();
        };
      },
    },
    ...[20, 100].flatMap((count) =>
      [false, true].flatMap((checkpointed) => {
        const label = `${count} members, ${checkpointed ? "a checkpoint in effect" : "no checkpoint"}`;
        /** A space whose administrator granted `count` writers, then checkpointed or not. */
        const once = async () => {
          const admin = await device();
          admin.setCheckpointPolicy({ propose: false, forget: false });
          const space = await admin.createSpaceOfKind("bench");
          for (let index = 0; index < count; index += 1) {
            const made = await device();
            await admin.advanced.grantDevice(space, made.id, made.advanced.deviceKeys(), "write");
          }
          if (checkpointed) await space.proposeCheckpoint();
          const doc = space.createDocument();
          return { admin, space, doc, at: 0 };
        };
        return [
          {
            name: `a membership change, ${label}`,
            once,
            prepare: async ({ admin, space }) => {
              const made = await device();
              const keys = made.advanced.deviceKeys();
              return async () => {
                await admin.advanced.grantDevice(space, made.id, keys, "write");
              };
            },
          },
          {
            name: `a refresh by an edit, ${label}`,
            once,
            prepare: async (shared) => async () => {
              const at = shared.at;
              shared.at += 1;
              await shared.doc.edit((edit) => edit.text(BODY).insert(at, "x"));
            },
          },
        ];
      }),
    ),
    ...[false, true].map((checkpointed) => ({
      name: `a refresh by an edit after 1,000 edits, 20 members, ${checkpointed ? "a checkpoint in effect" : "no checkpoint"}`,
      once: async () => {
        const admin = await device();
        admin.setCheckpointPolicy({ propose: false, forget: false });
        const space = await admin.createSpaceOfKind("bench");
        for (let index = 0; index < 20; index += 1) {
          const made = await device();
          await admin.advanced.grantDevice(space, made.id, made.advanced.deviceKeys(), "write");
        }
        if (checkpointed) await space.proposeCheckpoint();
        const doc = space.createDocument();
        for (let at = 0; at < 1000; at += 1) {
          await doc.edit((edit) => edit.text(BODY).insert(at, "x"));
        }
        return { doc, at: 1000 };
      },
      prepare: async (shared) => async () => {
        const at = shared.at;
        shared.at += 1;
        await shared.doc.edit((edit) => edit.text(BODY).insert(at, "x"));
      },
    })),
    {
      name: "close",
      close: async () => Promise.all(open.map((made) => made.close().catch(() => {}))),
    },
  ];
}

/** @param {number[]} values */
const median = (values) => {
  const sorted = [...values].sort((a, b) => a - b);
  const middle = Math.floor(sorted.length / 2);
  return sorted.length % 2 === 1 ? sorted[middle] : (sorted[middle - 1] + sorted[middle]) / 2;
};

/**
 * Runs every workload: one untimed warm-up, then `runs` timed runs. Resolves to
 * `[{ name, median, min, runs: [ms…] }]`.
 *
 * @param {any} frasil the package's API
 * @param {{ runs: number, log?: (line: string) => void }} options
 */
export async function measure(frasil, { runs, log = () => {} }) {
  const list = workloads(frasil, { runs });
  const results = [];
  for (const workload of list) {
    if (workload.close) {
      await workload.close();
      continue;
    }
    log(`  ${workload.name}`);
    const shared = workload.once ? await workload.once() : undefined;
    const times = [];
    for (let run = 0; run <= runs; run += 1) {
      const go = await workload.prepare(shared);
      const started = performance.now();
      await go();
      const elapsed = performance.now() - started;
      if (run > 0) times.push(elapsed);
    }
    results.push({
      name: workload.name,
      median: median(times),
      min: Math.min(...times),
      runs: times,
    });
  }
  return results;
}
