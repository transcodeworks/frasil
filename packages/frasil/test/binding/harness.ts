/**
 * What the scenarios share: a page of its own browser context per device, on the test origin,
 * with the package loaded, and the page-side agent's types (`page.js`). IDs cross between pages as
 * the hex the package gives them; keys as hex.
 */
import type { Browser, Page } from "@playwright/test";

import type { Blobs, Change, Device, Options, Review, Store, Version } from "../../src/index.js";

/** A device's three public keys, from `Advanced.deviceKeys`, as hex. */
export type DeviceKeysHex = string;

export interface Status {
  connected: boolean;
  reconnecting: boolean;
  reconnects: number;
  closed: string | null;
  spaces: string[];
  refused: { space: string; code: string }[];
  refusedChanges: number;
  recoveryEntries: number;
}

export interface Agent {
  told: string[];
  create(name: string): Promise<{ id: string; keys: DeviceKeysHex }>;
  open(name: string): Promise<{ id: string; continuity: string }>;
  makePerson(name: string): Promise<{ person: string; personalSpace: string }>;
  createRecoverySheet(): Promise<string>;
  registered(count: number): Promise<void>;
  recover(name: string, sheet: string): Promise<string>;
  recoverCode(name: string, sheet: string): Promise<string | null>;
  createSpace(): Promise<string>;
  spaces(): Promise<string[]>;
  grant(space: string, id: string, keys: DeviceKeysHex, level?: string): Promise<string>;
  grantGuest(space: string, id: string, keys: DeviceKeysHex, session: string): Promise<string>;
  leave(space: string): Promise<void>;
  editCode(space: string, doc: string, insert: string): Promise<string | null>;
  waitRemoved(space: string, id: string): Promise<void>;
  signedEvents(space: string): Promise<string[]>;
  follow(space: string): Promise<string>;
  ingest(
    space: string,
    events: string[],
  ): Promise<{ placed: number; wanted: number; refused: [number, string][] }>;
  level(space: string): Promise<string | undefined>;
  waitLevel(space: string, level: string): Promise<void>;
  setLevel(space: string, member: string, level: string): Promise<void>;
  flush(space: string): Promise<void>;
  setHomePeer(space: string, url: string): Promise<void>;
  knownPeers(space: string): Promise<string[]>;
  members(space: string): Promise<string[]>;
  createDocument(space: string): Promise<string>;
  documents(space: string): Promise<string[]>;
  edit(
    space: string,
    doc: string,
    index: number,
    deleteCount: number,
    insert: string,
  ): Promise<void>;
  text(space: string, doc: string): Promise<string | undefined>;
  history(space: string, doc: string): Promise<Change[]>;
  documentAt(
    space: string,
    doc: string,
    version: string,
  ): Promise<{ size: number; digest: string }>;
  createRecords(space: string): Promise<string>;
  writeCell(
    space: string,
    id: string,
    table: string,
    key: string,
    column: string,
    value: unknown,
    insert: boolean,
  ): Promise<void>;
  waitCell(
    space: string,
    id: string,
    table: string,
    key: string,
    column: string,
    value: unknown,
  ): Promise<void>;
  recordsHistory(space: string, id: string): Promise<Change[]>;
  recordsAt(
    space: string,
    id: string,
    change: string,
    table: string,
    key: string,
  ): Promise<Record<string, unknown> | undefined>;
  tag(space: string, doc: string, name: string): Promise<Version>;
  recordsTag(space: string, id: string, name: string): Promise<Version>;
  versions(space: string): Promise<Version[]>;
  untag(space: string, id: string): Promise<void>;
  versionsStream(space: string): Promise<string>;
  suggestCell(
    space: string,
    id: string,
    table: string,
    key: string,
    column: string,
    value: unknown,
  ): Promise<string>;
  recordsReview(space: string, id: string, suggestion: string): Promise<Review>;
  recordsAccept(space: string, id: string, suggestion: string): Promise<void>;
  putBlob(
    space: string,
    size: number,
    fromFile?: boolean,
  ): Promise<{ stream: string; blob: string; digest: string }>;
  blobDigest(space: string, stream: string, blob: string): Promise<string | null>;
  exportSpaceFile(
    space: string,
    kind: string,
    options?: {
      history?: "full" | "from-snapshot";
      objects?: "all" | "none" | number;
      wayIn?: ("keys" | { level: string; lifetime: number })[];
      seal?: string;
    },
  ): Promise<string>;
  appendSpaceFile(space: string, file: string): Promise<string>;
  /** The `expiresAt` of the invitation a `"wait-then-accept"` import holds, once shown. */
  waitingUntil: number | undefined;
  importSpaceFile(
    file: string,
    kind: string | string[],
    key?: string,
    decision?: "accept" | "decline" | "wait-then-accept",
  ): Promise<
    | {
        road: string;
        space: string;
        code?: undefined;
        accepted?: string;
        acceptCode?: string;
        declined?: boolean;
        inviter?: string;
        level?: string;
        label?: string | null;
      }
    | { code: string }
  >;
  sniffSpaceFile(file: string): Promise<{
    space: string;
    kind: string;
    heads: number;
    history: string;
    objects: number;
    exporter: string;
    wayIn: string;
  }>;
  joinCode?: string;
  joinViaPeer(name: string, delay?: number): Promise<string>;
  joined(): Promise<string>;
  joinPersonViaPeer(kept: string, person: string, name: string): Promise<string>;
  joinedPerson(): Promise<string[]>;
  admitDevice(text: string): Promise<string>;
  person(): Promise<string | null>;
  personalSpace(): Promise<string | null>;
  admit(space: string, text: string, level: string): Promise<string>;
  outbox(space: string): Promise<number>;
  connect(): Promise<void>;
  disconnect(): void;
  close(): Promise<void>;
  status(): Status;
  durable(space: string): Promise<void>;
  waitText(space: string, doc: string, expected: string): Promise<void>;
  erase(space: string): Promise<string[]>;
  refusedCode(space: string): Promise<string>;
  membershipCalls(name: string): Promise<{
    delivery: boolean;
    canSuggest: boolean;
    removeSelf: string | null;
    revoke: string | null;
  }>;
}

declare global {
  interface Window {
    agent: Agent;
    ready: Promise<boolean>;
  }
}

/**
 * The page's globals as the tests of reads and media use them: the package, the media helper,
 * the agent's device, and the helpers of `page.js`.
 */
export interface ReadsWindow {
  frasil: typeof import("../../src/index.js");
  media: typeof import("../../src/media.js");
  agent: Agent & {
    device: Device;
    /** The unlock key of the device `createWith` opened. */
    unlockKey: Uint8Array;
    createWith(name: string, options?: Options, store?: Store): Promise<string>;
    absent(space: string, data: Uint8Array): Promise<{ blobs: Blobs; blob: string }>;
  };
  helpers: {
    until<T>(check: () => T | Promise<T>, what: string, deadline?: number): Promise<T>;
    digest(data: Uint8Array): Promise<string>;
    pattern(size: number): Uint8Array;
    wav(seconds: number): Uint8Array;
  };
}

/** A database name no other test uses. */
export function uniqueName(label: string): string {
  return `frasil-test-${label}-${Math.random().toString(16).slice(2)}`;
}

/**
 * A page in a browser context of its own, so it shares no storage with another device's page,
 * with the package loaded. Errors the page throws fail the test that reads `errors`.
 */
export async function devicePage(browser: Browser): Promise<{ page: Page; errors: string[] }> {
  const context = await browser.newContext();
  const page = await context.newPage();
  const errors: string[] = [];
  page.on("pageerror", (error) => errors.push(`${error.name}: ${error.message}`));
  page.on("console", (message) => {
    if (message.type() === "error") errors.push(message.text());
  });
  await page.goto("/runner.html");
  await loaded(page, errors);
  return { page, errors };
}

/** Loads the runner page again, as a reload does, and waits for the package. */
export async function reload(page: Page): Promise<void> {
  await page.reload();
  await loaded(page, []);
}

/**
 * Waits until the page's module script has run: the package is loaded and the agent is there.
 * Fails with what the page reported if it has not within 30 seconds.
 */
async function loaded(page: Page, errors: string[]): Promise<void> {
  try {
    await page.waitForFunction(() => window.ready !== undefined, undefined, { timeout: 30_000 });
  } catch (error) {
    throw new Error(`the package did not load: ${errors.join("; ") || String(error)}`);
  }
  await page.evaluate(() => window.ready);
}
