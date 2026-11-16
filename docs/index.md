# A local index over many spaces

The `index` feature of `frasil` adds `frasil::index`: a typed SQLite cache of
the Records tables that many spaces hold. An application describes each table
as a plain struct, names the kind of space that feeds it, and queries the
cache with SQL, typed rows, live queries or Diesel. The cache is a copy that
the device can always rebuild from its replicas; the application writes
through Records, never through the cache.

```toml
[dependencies]
frasil = { version = "0.1", features = ["index"] }
```

## Tables

```rust,ignore
use frasil::index::{Index, Ref, Schema, Stored, Table, Time, create_space};

#[derive(Table)]
#[table(source = "shared")]
struct List {
    title: String,
}

#[derive(Table)]
#[table(source = "personal", suggestions)]
struct Item {
    list: Ref<List>,
    at: Time,
    done: bool,
    #[column(name = "comment")]
    note: Option<String>,
}

let schema = Schema::new().table::<List>().table::<Item>();
```

`#[derive(Table)]` makes a struct one table: its Records writes, its SQLite
table, and its part of the schema's JSON manifest (`Schema::manifest`), from
which code in another language reads the same schema.

- `source` (required): the kind of space whose Records feed the table.
- `name`: the table's name in Records and in SQL; the struct's name in snake
  case by default.
- `suggestions`: the table also holds open suggestions, one row per
  suggestion and row.
- `#[column(name = "…")]`: a column's name, the field's by default.

Fields are `String`, `i64`, `f64`, `bool`, `Vec<u8>`, `Time` (milliseconds
since 1970), `Ref<T>` (a row of another table, in any space), `RichText` (a
Loro document's text, stored as plain text) and `Option` of each.

Every table also has `_space` (the space's ID), `_key` (the row's key, in
hexadecimal), `_author` (who changed the row last: the person whose device
did, as the space knew it at that change, or the device when it was granted
directly) and `_changed_at` (the writer's claimed time, in milliseconds;
shown, never checked). A table with suggestions has `_suggested` and
`_suggestion`. The `_spaces` table lists each space that feeds the index:
`id`, `kind`, `synced_at` and `owner`.

## Spaces and writes

A space's kind is set when `create_space(&device, kind)` makes it, and kept
in its descriptor; a space with no kind feeds nothing, and neither does a
space this device keeps nothing of at rest (a guest's, when
`Space::keeps_nothing_at_rest` says so), since the index is a file on
disk. `create_space` returns
a `Writer`, and `Writer::of(&space)` gives the writer of an existing one:

```rust,ignore
let shared = create_space(&device, "shared").await?;
let list = shared.insert(&List { title: "Errands".into() }).await?;
let mine = create_space(&device, "personal").await?;
mine.insert(&Item { list, at: Time::now(), done: false, note: None }).await?;
```

`insert`, `put`, `update` (only the cells that changed) and `delete` each
write one change; `Writer::write` puts several in one `Batch`, and
`Batch::suggest` makes the batch a suggestion. A writer refuses a table
whose source is another kind.

Row keys are random, so a `Ref` joins rows across spaces.

## Opening and keeping it current

```rust,ignore
let index = Index::open(&device, dir.join("index.db"), schema).await?;
```

On wasm32 in a dedicated worker, `Index::open_in_browser(&device, name,
schema)` keeps the cache in the origin-private file system.

Opening brings the cache up to date. After that:

- `Index::follow` keeps the cache current; run it in a task of its own. A
  Records write refreshes only the rows it touched; any other change of a
  space, such as one of who may read it, a snapshot, or a document a rich
  text column shows, refreshes the whole space. Changes that arrive while a
  refresh runs are taken together. A refresh that fails is retried with
  backoff, from a tenth of a second up to thirty, and the others go on;
  `Index::follow_with(on_error)` hears of each failure. It returns once the
  device is gone.
- `Index::sync` reads every space again, and drops the rows of spaces the
  device no longer holds or reads.
- `Index::refresh(space)` reads one space again; `Index::try_refresh` does so
  unless another refresh runs, and says whether it did.
- `Index::refresh_row(space, &key)` updates one row right after this device
  wrote it, reading its merged value and last change from Records.
- `Index::rebuild` drops the cache and reads every space again.

A refresh reads a space's rows with their last changes in one pass
(`Records::rows_with_metadata`), and writes a table only when its rows
differ. `Index::revision` grows each time a refresh changes a table.

## Queries

```rust,ignore
let rows = index.query(
    "SELECT l.title, count(*) AS n FROM item i JOIN list l ON l._key = i.list GROUP BY l._key",
    &[],
)?;
let items: Vec<Stored<Item>> = index.all::<Item>()?;
let mut live = index.watch("SELECT * FROM item WHERE done = 0", vec![])?;
loop {
    let rows = live.next().await?; // now, then after each change
}
```

Queries run on a connection opened read-only, with `query_only` on and an
authorizer that allows reads alone, so a write fails rather than drifting
from the replicas. A live query (`Index::watch`) runs again each time a
refresh changes a table it reads; `Watch::distinct` makes it give its rows
only when they differ from the last it gave. `Index::table_changes` names
each table as the index changes it, for an application that reads the cache
its own way.
`Index::dangling` lists references to rows the cache does not hold.

With `index-diesel`, each derived table also has a Diesel `table!` module
named after it, and `Index::diesel` runs typed Diesel queries on the same
read-only connection. The crate that derives the tables depends on `diesel`
itself, at the version `frasil` uses.

`Index::update_local_metadata` and `Index::local_metadata` keep opaque
values on this device beside the cache, in one SQLite transaction; they
never enter a replica.

## In the browser package

The npm package's entry `@frasil/client/index` is the whole client, from a
build of the module that also holds the index; the default entry leaves
SQLite out. The module loads from a file, like the default entry's;
`@frasil/client/index/embedded` inlines it. Open the device and the index in a dedicated worker, with the
tables a manifest describes: the JSON `Schema::manifest` writes, or one
written by hand in the same form (`Schema::from_manifest` reads it in Rust).

```ts
// In a dedicated worker.
import { Device, Index, serveIndex, Storage } from "@frasil/client/index";

const device = await Device.open(Storage.indexedDb("my-app"), unlockKey);
const index = await Index.open(device, "my-app", manifest);
void index.follow((message) => console.warn(message));
serveIndex(index, self);

const open = index.watch("SELECT title FROM task WHERE done = 0");
const rows = index.query("SELECT count(*) AS n FROM task");
```

`index.watch` returns a store (see
[reading and caching](reading-and-caching.md)) whose subscribers hear of
its rows when they differ. A page reaches the worker's index with
`IndexClient`, which `@frasil/client/client` gives without loading any
WebAssembly (the other entries export it too, but they load their module):

```ts
import { IndexClient } from "@frasil/client/client";

const index = new IndexClient(worker);
const open = index.watch("SELECT title FROM task WHERE done = 0");
const rows = await index.query("SELECT count(*) AS n FROM task");
```

A worker that fails ends the client's queries in flight with `closed`;
`index.close()` does the same when the page terminates the worker, and every
later query rejects.

Use the index entry for every Frasil object of the worker: the index works
with devices of its own build of the module. `manifestToTypeScript`
writes the tables' row types.

## At rest

The file is encrypted under a key that `Device::derive_key` derives from the
device's application key: SQLCipher on native targets, and SQLite3 Multiple
Ciphers in its SQLCipher scheme on wasm32. The schema's version is a hash of
its manifest: a cache of another version, or one that does not open under
the key, is rebuilt from the replicas, with no network.

Apple targets build SQLCipher on CommonCrypto. Android, Linux and Windows
need OpenSSL's libcrypto: turn on `index-vendored-openssl` to build it from
source, or point `OPENSSL_DIR` at one. OpenSSL serves the cache's cipher
only; connections use ring. Leave `index-vendored-openssl` off for wasm32,
which does not build with it.

## Limits

- A space counts as readable while this device is a member of it at some
  level. A device that a space removed keeps its rows until its replica
  learns of the removal.
- `Index::sync` and `Index::refresh` read the whole space again, its rows
  and its history; `Index::follow` does so only after a change other than
  a Records write.
- `_changed_at` has second precision, and changes whose writer recorded no
  time have none.
