/**
 * File references (adapter-blobs.md, "References"; ext-libraries.md, "Holds"): a file stored once
 * in its library, used by any of the library's spaces.
 *
 * A space that uses a file another space stores puts a reference: an entry that names the stored
 * object and carries its own key, sealed in this space like any entry. The peer then keeps the file
 * for this space and serves it to its readers, who never join the source. A reference names one
 * fixed version of the file, and reads like any blob.
 *
 * ```ts
 * const cue = await show.referenceFrom(mediaBank, clip);
 * const details = await show.info(cue); // details.source is the media bank's space
 * const audio = show.getStream(cue);
 * ```
 *
 * @module
 */

import type { SpaceId } from "./space.js";
import type { BlobId } from "./streams.js";

/** What a blob stream holds under an ID. */
export interface BlobDetails {
  readonly id: BlobId;
  /** Its name, if it was given one. */
  readonly name?: string;
  /** Its media type, if it was given one. */
  readonly mediaType?: string;
  /** Its size in bytes. */
  readonly size: number;
  /** For a reference, the space that stores the file; absent for a blob this space stores. */
  readonly source?: SpaceId;
}
