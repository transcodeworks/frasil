/**
 * Signed application requests (ext-app-requests.md): a device signs a request with
 * `Device.signRequest`, and the application's server verifies it with {@link verifySignedRequest},
 * which learns the device and its person. In a Cloudflare Worker, import it from
 * `@frasil/client/module` after `load`.
 *
 * @module
 */

import type { MemberId, PersonId } from "./device.js";
import { FrasilError } from "./errors.js";
import { call, raw } from "./runtime.js";

/** A person's placed list event, and the server's first sight of it in seconds. */
export type ListEvent = [event: Uint8Array, firstSeen: number];

/**
 * What the server keeps durably, in its own storage (KV, D1 or a Durable Object in a Worker): per
 * subject of an access token, the person recorded at its first accepted request; per person, the
 * list events placed. Lists only grow.
 */
export interface DeviceLists {
  /** The person recorded for a subject; `undefined` if none. */
  recordedPerson(subject: string): Promise<PersonId | undefined>;
  /** Records a subject's person. */
  recordPerson(subject: string, person: PersonId): Promise<void>;
  /** A person's placed list events; empty when none is held. */
  list(person: PersonId): Promise<ListEvent[]>;
  /** Keeps a person's placed list events: the whole list. */
  keepList(person: PersonId, events: ListEvent[]): Promise<void>;
}

/**
 * The server's nonces, shared by every worker: `(device, nonce)` kept until `until`, seconds since
 * the Unix epoch, so that no request is accepted twice.
 */
export interface NonceStore {
  /**
   * Records `(device, nonce)` until `until`, unless it is recorded already until `now` or later,
   * as one atomic step. Resolves to whether it was unseen.
   */
  checkAndRecord(device: MemberId, nonce: Uint8Array, until: number, now: number): Promise<boolean>;
}

/** A request the verifier accepted. */
export interface VerifiedRequest {
  /** The person whose device signed it. */
  readonly person: PersonId;
  /** The device that signed it. */
  readonly device: MemberId;
  /**
   * The request names list events the server lacks: answer with `X-Frasil-List-Needed: 1`, and the
   * device delivers its list.
   */
  readonly listNeeded: boolean;
}

interface Verdict extends VerifiedRequest {
  readonly nonce?: { device: MemberId; nonce: Uint8Array; until: number; now: number };
  readonly recordPerson?: PersonId;
  readonly keptList?: { person: PersonId; events: ListEvent[] };
}

const personHeader = /^[0-9a-f]{64}$/;

/**
 * Verifies a request a device signed with `Device.signRequest`: `audience` is the server's own
 * origin, such as `https://api.example.org`, from its configuration; `subject` is the subject
 * (`sub`) of the access token the server verified already. The audience is never read from the
 * request: `request.url` in a Worker is built from its `Host` header, so a request signed for
 * another server could otherwise be sent here with that server's name. A request signed for
 * another origin is refused `bad_signature`. Reads a clone of the body, so the request can
 * still be read. A list delivery (`PUT /frasil/p1/device-list`) is placed on the way. Resolves to
 * the device and its person; rejects with the refusal's class, such as `unsigned`,
 * `bad_signature`, `expired`, `replayed`, `wrong_person`, `list_needed` or `not_a_signer`.
 */
export async function verifySignedRequest(
  request: Request,
  options: { audience: string; subject: string; deviceLists: DeviceLists; nonces: NonceStore },
): Promise<VerifiedRequest> {
  const { audience, subject, deviceLists, nonces } = options;
  const body = new Uint8Array(await request.clone().arrayBuffer());
  const headers: [string, string][] = [...request.headers];
  const claimed = request.headers.get("x-frasil-person-id")?.toLowerCase();
  const person = claimed !== undefined && personHeader.test(claimed) ? claimed : undefined;
  const [recorded, list] = await Promise.all([
    deviceLists.recordedPerson(subject),
    person === undefined ? Promise.resolve([]) : deviceLists.list(person),
  ]);
  const verdict = call(
    () =>
      raw.verifyRequest(
        audience,
        subject,
        request.method,
        request.url,
        headers,
        body,
        recorded,
        person,
        list,
      ) as Verdict,
  );
  if (verdict.nonce !== undefined) {
    const { device, nonce, until, now } = verdict.nonce;
    if (!(await nonces.checkAndRecord(device, nonce, until, now))) {
      throw new FrasilError("replayed", "the request was accepted before", {
        class: "Replayed",
      });
    }
  }
  if (verdict.recordPerson !== undefined) {
    await deviceLists.recordPerson(subject, verdict.recordPerson);
  }
  if (verdict.keptList !== undefined) {
    await deviceLists.keepList(verdict.keptList.person, verdict.keptList.events);
  }
  return { person: verdict.person, device: verdict.device, listNeeded: verdict.listNeeded };
}
