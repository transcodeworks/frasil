# The drive extension
Protocol 1. Vectors: [ext-drive.json](vectors/ext-drive.json).

This document specifies a **drive**: a tree of folders and named entries,
held in one Loro document of a space, that every application of the space
reads and writes alike. An entry is a folder, a file that names a blob of a
Blobs stream, or a document that names a Loro document or a Records stream
of the space. Entries are renamed, moved, sent to the trash, restored and
purged; a file takes new versions of its blob, and keeps each version's
parents so that every replica reads the same heads and the same
conflicts; and concurrent changes merge without any party ordering them.

It builds on [adapter-loro.md](adapter-loro.md), whose documents hold a
drive, and depends on [overview.md](overview.md) for conventions and error
classes, on [units.md](units.md) for stream IDs, and on
[adapter-blobs.md](adapter-blobs.md) and
[adapter-records.md](adapter-records.md) for the streams an entry names.

A writer that also implements [ext-file-versions.md](ext-file-versions.md)
tells peers which objects a new version replaces, so that they keep a
bounded number of old versions. Nothing in this document needs it.

A core implementation, or one with the Loro adapter and without this
extension:

| What this document defines | Such an implementation |
|---|---|
| A drive document | a Loro document like any other: checked, merged and synced by [adapter-loro.md](adapter-loro.md) |
| Entries that name streams and blobs | nothing: streams and objects are kept and collected by their own rules |

Nothing in a log, roster, unit or object refers to a drive, so no
replica's verdict depends on this extension. Its checks are a writer's,
before it writes, and a reader's, as it reads.

## 1. Overview

- A drive is one Loro document. Its root map `document` names its kind,
  `frasil:drive`; its root tree `entries` holds the entries as nodes of
  Loro's movable tree, each with a metadata map.
- Every change is a set of ordinary Loro operations, written as units of
  the document ([adapter-loro.md](adapter-loro.md), section 3.1). Every
  replica that holds the same units reads the same tree.
- Concurrent moves never make a cycle, concurrent renames keep one name,
  and two entries may share a name: readers number the later ones alike.
- Entries in the trash keep their place, and come back where they were.
  A purge forgets an entry and what is inside it for good.
- A file's versions are records on the entry, each naming the versions it
  was made from. A version no other names is a **head**. One head is the
  ordinary case; two or more are a **conflict**, the same at every
  replica, which any writer resolves by writing a version that names
  every head. A blob's handle is never used for a second version.
- The drive is extensible. An application adds its own fields to an
  entry's `meta` map, its own entry kinds, and its own root containers.
  Readers keep what they do not know, and writers leave it alone.
- The drive grants nothing: who reads and writes it is who reads and
  writes its space.

## 2. Formats

### 2.1 Values

| Value | Form |
|---|---|
| Entry ID | 32 lower-case hexadecimal digits: 16 bytes drawn from a cryptographically secure source |
| Name | a string of 1 to 255 bytes of UTF-8, without `/` and without a control character (Unicode category Cc) |
| Kind string | a string of 1 to 64 bytes of UTF-8, without a control character or white space (Unicode `White_Space`) |
| Stream ID | 32 lower-case hexadecimal digits, not all zero: a stream ID of the drive's space ([units.md](units.md), section 2.6) |
| Handle | 32 lower-case hexadecimal digits: a blob's handle in its Blobs stream ([adapter-blobs.md](adapter-blobs.md), section 2.1) |
| Media type | a string of at most 255 bytes: `token/token`, optionally followed by `;` and printable ASCII, where a token is one or more of the ASCII letters, digits and ``!#$%&'*+.^_`\|~-`` |
| Count | an integer from 0 to 2^53 − 1 |
| Time | a count: seconds since 1970-01-01T00:00:00Z by the writer's wall clock |
| Meta key | a string of 1 to 255 bytes of UTF-8, without a control character |
| Meta value | a Loro value that is not a container: null, a boolean, a number, a string, bytes, or a list or map of such values |

- Names are compared byte for byte. A writer MAY normalise a name before
  it writes it; a reader never does.
- A writer writes a count as a Loro `I64`. A reader reads a count from an
  `I64` in range, or from a `Double` that holds an integer in range, and
  reads anything else as absent.
- A writer whose wall clock is not known ([overview.md](overview.md),
  section 6) writes no time where this document makes it optional, and 0
  where it does not.

### 2.2 The drive document

A drive is a Loro document, a stream of type `frasil:loro`, with these
root containers:

| Container | Type | Holds |
|---|---|---|
| `document` | map | `kind`: the string `frasil:drive` |
| `entries` | tree, fractional index enabled | the entries, one node each (section 2.3) |
| `purged` | map | each stream ID whose document entry was purged, to the purge's time |

- The creator of a drive writes `document`'s `kind` in the drive's first
  unit. A document whose `document` map does not hold `kind` equal to
  `frasil:drive` is not a drive (`NotADrive`).
- A reader ignores every other root container and every other key of
  `document`. A writer never deletes or changes them, and never deletes
  `kind`.

### 2.3 Entries

Each node of `entries` is one entry. Its metadata map holds:

| Key | Kinds | Value | When |
|---|---|---|---|
| `id` | all | entry ID | always |
| `kind` | all | kind string: `folder`, `file`, `document` or an application's kind | always |
| `name` | all | name | always |
| `added` | all | time the entry was added | optional |
| `at` | all | time of its last rename, move or restore | optional |
| `trashed` | all | time it was sent to the trash itself | while it is there |
| `stream` | `file`, `document` | stream ID: a Blobs stream for a file; a Loro document or a Records stream for a document | always |
| `blob` | `file` | handle: the blob in `stream` | always |
| `size` | `file` | count: the blob's plaintext bytes | optional |
| `type` | `file` | media type of the blob | optional |
| `versions` | `file` | map of handles to version records (section 2.4): the file's versions | always |
| `docKind` | `document` | kind string: what the document is, as the application that made it names it | always |
| `meta` | all | map of meta keys to meta values: the applications' own fields | always |

- A **folder** holds entries. A **file** names a blob: its bytes are what
  the Blobs stream's entry names, an object of the space or a reference to
  a file stored elsewhere. A
  **document** names a stream of the space that holds an application's
  document; `docKind` says which application's, such as
  `example.spreadsheet`.
- `size` and `type` copy what the Blobs entry says, for listings. The
  Blobs entry is authoritative, and so is the stream's adapter type over
  `docKind`.
- A file or document entry holds no entries. Whether an entry of an
  application's kind holds entries is that kind's definition.
- **One entry per stream.** A writer adds no document entry for a stream
  that an entry names already, or whose entry was purged (`purged`). When
  concurrent writers add two, the first in order (section 3.2) is the
  stream's entry.
- **Application kinds.** A kind this document defines later contains
  neither `.` nor `:`. An application's own kind MUST contain one, such as
  `example.note`, and an application SHOULD begin its meta keys with a
  prefix of its own followed by `.`.
- A writer MUST NOT write a key of this table with another form, and
  MUST NOT write keys other than these in the metadata map; an
  application's fields go in `meta`.

### 2.4 Versions

`versions` is a map container whose keys are handles and whose values are
**version records**. A record is a meta value, a map:

| Key | Value | When |
|---|---|---|
| `stream` | stream ID: the Blobs stream of the version's blob | always |
| `size` | count: the blob's plaintext bytes | optional |
| `at` | time the version was written | optional |
| `parents` | list of 0 to 64 handles, no handle twice, none the record's own: the versions this one was made from | always |

- A version is a blob: the record's key is its handle, and `stream` its
  stream. The entry's `blob` and `stream` name one of the versions, the
  one a reader shows as the file (section 3.3).
- `parents` are what the writer made the version from: the version its
  copy of the file came from; every head, when it resolves a conflict;
  none, when it has no base. A parent need not have a record: its record
  may have been forgotten (section 3.4), or never written.
- A record is written once, by Add or Set blob, and never changed. A
  writer removes one only by Forget version (section 3.4).
- A record that does not have this form reads as absent, and so does a
  key that is not a handle.
- The **heads** of a file are the handles of its records that no record
  of the file names in `parents`. A file whose `versions` holds no
  record, or whose records name each other so that none is a head, has
  one head, `blob`, with no parents.
- A file whose heads are two or more is **in conflict**.

### 2.5 Error classes

| Class | Meaning | Sort |
|---|---|---|
| `NotADrive` | a document whose `document` map does not name the kind `frasil:drive` | final, for that document |
| `InvalidValue` | a name, entry ID, kind string, stream ID, handle, media type, count, meta key or version record of the wrong form | decision: nothing is written |
| `NoSuchEntry` | a change that names an entry the drive does not hold | decision |
| `EntryExists` | an entry added under an entry ID the drive holds | decision |
| `CannotHold` | an entry added or moved into an entry that is not a folder | decision |
| `MoveIntoItself` | a folder moved into itself or into an entry inside it | decision |
| `AlreadyListed` | a document entry added for a stream that has an entry, or whose entry was purged | decision |
| `AlreadyTrashed` | an entry sent to the trash that was sent there itself already | decision |
| `NotTrashed` | an entry restored that was not sent to the trash itself | decision |
| `NotAFile` | a Set blob or Forget version of an entry whose kind is not `file` | decision |
| `VersionExists` | a Set blob under a handle that has a record already | decision |
| `NoSuchVersion` | a Forget version of a handle under which `versions` holds nothing | decision |
| `VersionIsHead` | a Forget version of a head | decision |
| `VersionHasParents` | a Forget version of a record one of whose parents has a record | decision |

## 3. Procedures

### 3.1 Creating a drive

A writer creates a drive as a new Loro document of the space, and writes
`kind` into its `document` map as the document's first unit. An
application opens an existing document as a drive only if it is one;
otherwise it refuses with `NotADrive` and writes nothing.

### 3.2 Reading the tree

A reader reads a drive whole, in this order:

```text
read(document):
  1. document's `kind` is the string `frasil:drive`.        else NotADrive
  2. Walk `entries` depth first: the roots, then each node's
     children, before the node's next sibling; siblings in
     Loro's order of the tree's children.
  3. At each node, read its metadata map. Skip the node, and
     every node inside it, when:
       - `id` is not an entry ID, `kind` not a kind string,
         or `name` not a string;
       - an entry read earlier in the walk has the same `id`;
       - its kind is `file`, and `stream` is not a stream ID
         or `blob` not a handle;
       - its kind is `document`, and `stream` is not a stream
         ID or `docKind` not a kind string.
  4. Otherwise it is an entry. Its order is its place among
     the entries in the walk, from 0. Its parent is the entry
     of its tree parent when that entry is a folder or of an
     application's kind; otherwise, and for a root, it has
     none, and it shows at the root.
  5. Read `added`, `at`, `trashed`'s time and `size` as
     counts, `type` as a media type, `meta` as a map, and
     for a file `versions` as a map of handles to version
     records (section 2.4); each that does not have its
     form reads as absent, an absent `meta` as an empty
     map, and an absent `versions` as one with no record.
```

- An entry is **trashed itself** when its metadata map holds `trashed`,
  whatever its value; its time is the count, or 0 when it is not one.
- An entry is **in the trash** when it, or an entry above it, is trashed
  itself.
- A name that is a string of another form than section 2.1's is read and
  shown as it is.
- A node that is skipped stays in the document. Writers leave it, and
  what is inside it, as it is.

### 3.3 What a reader shows

- **A folder's listing** is the entries whose parent it is, or the root's
  entries, that are not trashed themselves, in order, each under its
  shown name. A folder in the trash has a listing too.
- **Shown names.** The first entry of a listing with a name shows it. A
  later entry with the same name shows `name (n)`, with the smallest `n`
  from 2 such that the result is neither shown already in the listing nor
  the name of any entry of the listing:

  ```text
  numbered(name, n) = for a file whose name has a "." after its first
                      byte: the part before its last ".", " (n)", then
                      the rest; otherwise name, " (n)"
  ```

  `n` is written in decimal, without leading zeros.
- **The trash** lists each entry that is trashed itself and whose parent,
  if any, is not in the trash: the greatest time first, then in order.
  Each shows its own name.
- **A stream's entry** is the first entry in order whose kind is
  `document` and whose `stream` is the stream.
- **A file** shows `blob`, in `stream`, under its shown name: its
  **current version**. Its **versions** are its records. Each head other
  than `blob`'s handle is an **other head**; an application shows it
  beside the file, under a name of its own that says which version it
  is, and never in place of the current version until a writer resolves
  the conflict. A version whose blob no peer or member serves is shown
  as unavailable; a peer may have collected it
  ([ext-file-versions.md](ext-file-versions.md)).
- **A version's author** is the device that signed the unit whose
  operations wrote the version's record, and the person whose list held
  that device at the unit's place, as the roster names them
  ([roster.md](roster.md), [identity.md](identity.md)). A record is
  written once (section 2.4), so the Loro peer of its key's last write is
  the one incarnation, and so the one device, that wrote it
  ([adapter-loro.md](adapter-loro.md)). Nothing in the record names an
  author, and nothing a writer puts in a record changes who a reader
  shows. A record the writer of a Set blob wrote for the current version
  (section 3.4) shows that writer. A reader that does not hold the unit
  shows no author.
- **Open conflicts** are the files in conflict. An application that
  reports a drive as settled reports them first.

### 3.4 Changes

Each change is one unit of the drive, or part of one with changes made
together (below), and the operations below are all of its operations.
`at` is the writer's time (section 2.1).

| Change | Operations |
|---|---|
| Add | create a node as the last child of the parent's node, or as the last root; set `id`, `kind`, `name`, `added` and `at`, the kind's own keys, and `meta` as a new, empty map; for a file, `versions` as a new map holding `blob`'s record, with `stream`, `size` and `at` as the entry's and no parents |
| Rename | set `name` and `at` |
| Move | move the node to be the last child of the new parent's node, or the last root; set `at` |
| Trash | set `trashed` to `at`, or to 0 |
| Restore | delete `trashed`; set `at` |
| Purge | set `purged`'s key of each stream named by a document entry whose node is the entry's node or inside it, to `at`, or to 0; then delete the entry's node, which deletes every node inside it |
| Set meta | set the key in `meta`, first creating `meta` as a new map if the node has none |
| Delete meta | delete the key from `meta` |
| Set blob | when `parents` name the entry's `blob`: set `blob`, `stream` and `at`, and set `size` and `type`, or delete each the writer does not know. Then, in every case, set the new handle's key in `versions` to its record, first creating `versions` as a new map if the node has none. When `parents` do not name `blob` and `versions` holds no record of it, first set `blob`'s key to a record of its `stream` and `size`, with no `at` and no parents, so that the current version stays a head |
| Forget version | delete the handle's key from `versions` |

Before it writes, a writer reads the drive (section 3.2) and checks the
change, in order; the first check that fails refuses it, and nothing is
written:

```text
every change:     1. The document is a drive.               else NotADrive
                  2. Each value it writes has its form.      else InvalidValue
add:              3. No entry has the new entry ID.          else EntryExists
                  4. The parent, if any, is an entry.        else NoSuchEntry
                  5. The parent, if any, is a folder.        else CannotHold
                  6. For a document: the stream has no entry,
                     and `purged` does not hold it.          else AlreadyListed
rename, move,
trash, restore,
purge, meta:      3. The entry is an entry.                  else NoSuchEntry
move:             4. The new parent, if any, is an entry.    else NoSuchEntry
                  5. The new parent, if any, is a folder.    else CannotHold
                  6. The new parent's node is not the
                     entry's node, nor inside it in
                     `entries`.                              else MoveIntoItself
trash:            4. The entry is not trashed itself.        else AlreadyTrashed
restore:          4. The entry is trashed itself.            else NotTrashed
set blob,
forget version:   3. The entry is an entry.                  else NoSuchEntry
                  4. Its kind is `file`.                     else NotAFile
set blob:         5. `versions` holds no record under the
                     new handle.                             else VersionExists
forget version:   5. `versions` holds a value under the
                     handle, of any form.                    else NoSuchVersion
                  6. The handle is not a head.               else VersionIsHead
                  7. No parent of the record has a record.   else VersionHasParents
```

A value of the wrong form under the handle is no record and names no
parents, so check 7 passes it; unless the handle is a head, Forget
version deletes it.

- An add writes only `folder`, `file` or `document` entries, and only into
  a folder or the root. An application that adds an entry of its own kind,
  or into one, does so by that kind's definition.
- A writer MAY rename, move, trash, restore, purge and change the `meta`
  of an entry of a kind it does not know; it writes no other key of it.
- **Putting a version.** Before a Set blob, the writer puts the blob
  under a new handle in a Blobs stream of the space, uploading its
  object first ([adapter-blobs.md](adapter-blobs.md); [units.md](units.md),
  section 3.4). It MUST NOT put a version under a handle that has a
  record, or that it has used for any version: a put to a used handle
  resolves by stamp, and one of two concurrent saves would vanish
  unseen. A writer that implements
  [ext-file-versions.md](ext-file-versions.md) names, in that put's
  supersessions, each parent whose entry it holds in the same stream,
  as that document says. Without it, peers keep every version until a
  writer removes its handle.
- **Parents.** A plain save names the one version the writer's copy came
  from, whether or not it is still a head: a save from a stale copy
  becomes a second head, and the conflict is data every replica reads.
  A version whose parents do not name the entry's `blob` does not take
  the file's place: the current version stays until a writer resolves
  the conflict.
  A resolution names every head of the file as it read them, and its blob
  is whichever the person or a merge chose: one head's bytes put again
  under a new handle, or a merge of several. Nothing in the drive judges
  the choice. Any writer may resolve.
- **Restoring a version.** A writer makes an older version the current
  version again by putting its bytes again under a new handle, as a new
  version, and a Set blob whose parents are every head of the file. The
  old version keeps its record; a restore of a file in conflict resolves
  it.
- **Forgetting versions.** Records are small and a file may have many.
  A writer MAY forget records from the oldest end: a record that is not
  a head and whose parents have no record. Forgetting in that order never
  makes a head of a record that was not one. A writer SHOULD keep the
  records of the versions it expects a peer to serve, so that readers
  can list them, and MAY remove a forgotten version's handle from its
  Blobs stream, which lets peers collect its object as any unreferenced
  one.
- **Released blobs.** A purge releases each blob, as a stream ID and a
  handle, that a file entry whose node the purge deletes names, by `blob`
  or by a record of `versions`, and that no other entry of the drive
  names. The writer MAY
  remove released blobs from their Blobs streams; nothing in the drive
  requires it, and another application may still use them.
- **Changes made together.** A writer MAY write several changes as one
  unit, such as an entry added with its `meta`, or a purge of an entry
  with the entries that belong to it. It checks each change against the
  drive as the changes before it in the unit leave it; if a check fails,
  it writes none of them.
- A writer MUST NOT delete a node but by a purge, and MUST NOT write the
  metadata of a node it skipped.

### 3.5 Concurrent changes

- Loro's movable tree merges moves. Every replica that holds the same
  operations has the same tree, and the tree never has a cycle: of
  concurrent moves that together would make one, the one that would close
  it in Loro's order of operations has no effect, at every replica.
- Each key of a metadata map, and of `meta`, takes the value of the last
  writer in Loro's order. A concurrent rename and move of one entry both
  take effect; of two concurrent renames, one name stays, the same at
  every replica.
- Two concurrent Set blobs of one file keep one `blob`, the same at every
  replica, and both records, since each is under its own handle: both are
  heads, and the file is in conflict at every replica. The `blob` kept is
  one of the heads. A later Set blob that names both as parents ends the
  conflict.
- A Set blob concurrent with a Forget version of its parent leaves a
  record whose parent has no record. The heads are the same as if the
  parent were there.
- A Set blob concurrent with a purge of the entry is purged with it.
- An entry moved, concurrently with a purge, into the purged entry is
  purged with it or stays, as Loro's order of the two operations decides,
  the same at every replica.
- A move into a folder that is concurrently purged, or a trash concurrent
  with a restore, resolves the same way: by the operations, never by the
  time a writer wrote.
- Two entries with one name are both kept; readers number the later one
  (section 3.3).

### 3.6 Extending a drive

An application layers its own meaning on a drive without changing this
format:

- **Fields of an entry** go in its `meta`, such as a folder's type or a
  file's thumbnail, under the application's prefix.
- **Entry kinds** of its own, such as a note that holds attachments,
  follow section 2.3's rules for application kinds. Every reader lists
  them, keeps what is inside them, and lets a person rename, move, trash
  and purge them.
- **Records of the whole drive** go in root containers of its own.

A reader that does not know a field, kind or container shows the drive as
the rest of it says, and every writer keeps it, so applications that know
different extensions share one drive.

## 4. Security considerations

- **The drive grants nothing.** Every writer of the space can rename,
  move, trash and purge every entry, and every reader of the space sees
  every name. Content that some members must not see belongs in a
  restricted space ([ext-restricted-spaces.md](ext-restricted-spaces.md))
  and a drive of its own.
- **Entries are claims.** An entry's `docKind`, `size` and `type` are what
  its writer said. A reader takes what a target is from its stream: the
  adapter type, the Blobs entry, and the document's own content.
- **Names are a writer's, not a filesystem's.** A name may be `.` or
  `..`, may differ from a sibling's only in case or in Unicode
  normalisation, and may be one that a filesystem reserves or refuses,
  such as `CON` or a name ending in a dot or a space. This document says
  nothing of any filesystem, and a reader never normalises. An application
  that mirrors a drive to a filesystem treats each name as untrusted input:
  it maps or refuses names its filesystem would read as a path step, a
  device or another entry's file, and never joins a name to a path
  unchecked, or a writer could make it write outside the folder or over a
  sibling's file.
- **Versions are claims too.** A writer chooses a version's parents. It
  can make a conflict appear by naming none, or make one disappear by
  naming every head with bytes of its own. Both are what a writer of the
  space can do already by setting `blob`; the records make what it did
  visible to every reader.
- **A purge forgets an entry, not its target.** The stream and the blob
  stay in the space until they are removed by their own rules, and a
  purge does not undo what a member read before.
- **Skipped nodes.** A writer can hide a subtree from readers by writing a
  malformed `id` on its top node. It could trash or purge the subtree as
  well; skipping costs nothing more, and keeps the subtree recoverable.
- **Times are the writer's.** `added`, `at` and `trashed` order the trash
  and inform the person; nothing merges by them, so a wrong clock changes
  no tree.
- **Entry IDs are random**, so they say nothing of a name or a place.

## 5. Test vectors

[ext-drive.json](vectors/ext-drive.json). A tree is written as the root
containers' values: `document` and `purged` as maps, and `entries` as a
list of roots, each node as `{"fields": map, "children": list}`, where
`fields` is the node's metadata map and children are in order. In a map, an integer is an `I64`, a number with a fraction or an
exponent a `Double`, and an object a map container, except inside
`versions`, where an object is a version record, a map value (section
2.4). An implementation
builds the document by creating each node as its parent's last child.

- `parameters`: the kind, the root containers, and the limits of section
  2.1.
- `values`: names, entry IDs, kind strings, stream IDs, handles, media
  types and meta keys, each with whether it has its form; and counts as
  Loro values, each with the count it reads as, or null.
- `names`: shown names of listings, by section 3.3.
- `reading`: trees and what a reader reads from each, by section 3.2: the
  entries in order with their fields, every folder's listing, the trash,
  each stream's entry, and the entries in the trash. They cover a node
  without an ID, a duplicate ID, a file without its blob, an application's
  kind with an entry inside it, an entry under a file, a count written as
  a `Double`, a trashed folder, a file with no `versions`, one whose
  records name each other in a cycle, one with a record of the wrong
  form, one with two heads, and a document that is not a drive. Each
  file's heads, and whether it is in conflict, are read with it.
- `changes`: a tree, a change and its verdict, with the tree after it and,
  for a purge, the released blobs, a file's versions among them: each
  change of section 3.4 applied, and each refusal of its checks.
- `versions`: Set blob as a plain save, as a save from a stale copy,
  which leaves `blob` alone, as a resolution naming two heads
  with a merged blob, and as a pick of one head's bytes under a new
  handle; a first Set blob on a file without records; one with no
  parents; Set blob on a folder (`NotAFile`) and under a used handle
  (`VersionExists`); Forget version of the oldest record, of a head
  (`VersionIsHead`), of a record whose parent has a record
  (`VersionHasParents`), of a handle without one (`NoSuchVersion`) and
  of a value of the wrong form, which is deleted;
  and two concurrent Set blobs merged in both of Loro's orders, with the
  `blob` kept and the two heads.
