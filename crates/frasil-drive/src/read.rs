//! Section 3.2, Reading the tree, and 3.3, What a reader shows.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use loro::{Container, LoroDoc, LoroMap, LoroValue, TreeID, TreeParentId, ValueOrContainer};

use crate::values::{
    MAX_PARENTS, is_entry_id, is_handle, is_kind_string, is_media_type, is_stream_id, read_count,
};
use crate::{DOCUMENT, DOCUMENT_KIND, ENTRIES, Error, FILE, FOLDER, KIND, PURGED};

/// A version record of a file (section 2.4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Version {
    /// The Blobs stream of the version's blob, in hexadecimal.
    pub stream: String,
    /// The blob's plaintext bytes, as the record says.
    pub size: Option<u64>,
    /// When the version was written.
    pub at: Option<u64>,
    /// The handles of the versions this one was made from.
    pub parents: Vec<String>,
    /// The Loro peer that wrote the record: a record is written once, so
    /// its last editor is its writer (section 3.3, "A version's author").
    pub writer: Option<u64>,
}

/// What an entry is, with its own fields.
#[derive(Clone, Debug, PartialEq)]
pub enum Kind {
    /// A folder, which holds entries.
    Folder,
    /// A blob of a Blobs stream.
    File {
        /// The Blobs stream's ID, in hexadecimal.
        stream: String,
        /// The blob's handle in it, in hexadecimal.
        blob: String,
        /// Its plaintext bytes, as the entry says.
        size: Option<u64>,
        /// Its media type, as the entry says.
        media_type: Option<String>,
        /// Its version records, by handle.
        versions: BTreeMap<String, Version>,
        /// Its heads, sorted (section 2.4).
        heads: Vec<String>,
    },
    /// A stream of the space that holds an application's document.
    Document {
        /// The stream's ID, in hexadecimal.
        stream: String,
        /// What the document is, as its application names it.
        kind: String,
    },
    /// An application's own kind, which this reader does not interpret.
    Other(String),
}

impl Kind {
    /// The kind string the entry's `kind` holds.
    pub fn name(&self) -> &str {
        match self {
            Kind::Folder => FOLDER,
            Kind::File { .. } => FILE,
            Kind::Document { .. } => DOCUMENT_KIND,
            Kind::Other(kind) => kind,
        }
    }

    /// Whether entries inside an entry of this kind have it as their parent:
    /// a folder's, and an application's kind's.
    pub fn holds(&self) -> bool {
        !matches!(self, Kind::File { .. } | Kind::Document { .. })
    }
}

/// An entry, as a reader reads it.
#[derive(Clone, Debug, PartialEq)]
pub struct Entry {
    /// Its entry ID.
    pub id: String,
    /// What it is.
    pub kind: Kind,
    /// Its own name.
    pub name: String,
    /// The entry it is in, or `None` at the root.
    pub parent: Option<String>,
    /// Its place among the entries, from 0.
    pub order: usize,
    /// When it was added.
    pub added: Option<u64>,
    /// When it was last renamed, moved or restored.
    pub at: Option<u64>,
    /// When it was sent to the trash itself, while it is there.
    pub trashed: Option<u64>,
    /// The applications' own fields.
    pub meta: BTreeMap<String, LoroValue>,
    /// Its node in the tree.
    pub node: TreeID,
}

impl Entry {
    /// Whether it is a file with two or more heads (section 2.4).
    pub fn in_conflict(&self) -> bool {
        matches!(&self.kind, Kind::File { heads, .. } if heads.len() > 1)
    }
}

/// An entry of a listing, under its shown name.
#[derive(Clone, Debug, PartialEq)]
pub struct Shown<'a> {
    /// The entry.
    pub entry: &'a Entry,
    /// The name the listing shows for it.
    pub name: String,
}

/// A drive, as a reader reads it.
#[derive(Clone, Debug, Default)]
pub struct Tree {
    entries: Vec<Entry>,
    by_id: HashMap<String, usize>,
    by_node: HashMap<TreeID, usize>,
    /// Every node, readable or not, to its parent node.
    node_parent: HashMap<TreeID, Option<TreeID>>,
    purged: BTreeMap<String, LoroValue>,
}

fn string(map: &LoroMap, key: &str) -> Option<String> {
    match map.get(key) {
        Some(ValueOrContainer::Value(LoroValue::String(text))) => Some(text.to_string()),
        _ => None,
    }
}

fn value(map: &LoroMap, key: &str) -> Option<LoroValue> {
    map.get(key).map(|found| found.get_deep_value())
}

fn count(map: &LoroMap, key: &str) -> Option<u64> {
    value(map, key).as_ref().and_then(read_count)
}

/// The `meta` map container of a node, if it has one.
pub(crate) fn meta_map(fields: &LoroMap) -> Option<LoroMap> {
    match fields.get("meta") {
        Some(ValueOrContainer::Container(Container::Map(map))) => Some(map),
        _ => None,
    }
}

/// A version record of its form (section 2.4), or `None`.
fn read_version(handle: &str, value: &LoroValue) -> Option<Version> {
    let LoroValue::Map(record) = value else {
        return None;
    };
    if !is_handle(handle)
        || record
            .keys()
            .any(|key| !matches!(key.as_str(), "stream" | "size" | "at" | "parents"))
    {
        return None;
    }
    let Some(LoroValue::String(stream)) = record.get("stream") else {
        return None;
    };
    let Some(LoroValue::List(listed)) = record.get("parents") else {
        return None;
    };
    let mut parents = Vec::with_capacity(listed.len());
    for parent in listed.iter() {
        match parent {
            LoroValue::String(parent) => parents.push(parent.to_string()),
            _ => return None,
        }
    }
    if !is_stream_id(stream) || !is_parents(&parents, handle) {
        return None;
    }
    // An optional field of the wrong form makes the record not of the form:
    // it reads as absent, not as a record without that field.
    let optional = |key: &str| match record.get(key) {
        None => Some(None),
        Some(value) => read_count(value).map(Some),
    };
    Some(Version {
        stream: stream.to_string(),
        size: optional("size")?,
        at: optional("at")?,
        parents,
        writer: None,
    })
}

/// Whether handles have the form of a record's `parents` (section 2.4): at
/// most 64 handles, no handle twice, none the record's own.
pub(crate) fn is_parents(parents: &[String], own: &str) -> bool {
    let unique: HashSet<&String> = parents.iter().collect();
    parents.len() <= MAX_PARENTS
        && unique.len() == parents.len()
        && parents
            .iter()
            .all(|parent| is_handle(parent) && parent != own)
}

/// The `versions` map container of a node, if it has one.
pub(crate) fn versions_map(fields: &LoroMap) -> Option<LoroMap> {
    match fields.get("versions") {
        Some(ValueOrContainer::Container(Container::Map(map))) => Some(map),
        _ => None,
    }
}

/// A file's records that have their form, by handle.
fn read_versions(fields: &LoroMap) -> BTreeMap<String, Version> {
    let Some(map) = versions_map(fields) else {
        return BTreeMap::new();
    };
    let LoroValue::Map(records) = map.get_value() else {
        return BTreeMap::new();
    };
    records
        .iter()
        .filter_map(|(handle, value)| {
            let mut version = read_version(handle, value)?;
            version.writer = map.get_last_editor(handle);
            Some((handle.clone(), version))
        })
        .collect()
}

/// The heads of a file (section 2.4): the handles no record names in
/// `parents`, or `blob` alone when there is no such handle.
fn heads(blob: &str, versions: &BTreeMap<String, Version>) -> Vec<String> {
    let named: BTreeSet<&String> = versions.values().flat_map(|v| &v.parents).collect();
    let found: Vec<String> = versions
        .keys()
        .filter(|handle| !named.contains(handle))
        .cloned()
        .collect();
    if found.is_empty() {
        vec![blob.to_owned()]
    } else {
        found
    }
}

/// Section 3.2, steps 3 and 5, for one node's metadata map.
fn parse(fields: &LoroMap, node: TreeID) -> Option<Entry> {
    let id = string(fields, "id").filter(|id| is_entry_id(id))?;
    let kind_name = string(fields, "kind").filter(|kind| is_kind_string(kind))?;
    let name = string(fields, "name")?;
    let kind = match kind_name.as_str() {
        FOLDER => Kind::Folder,
        FILE => {
            let stream = string(fields, "stream").filter(|s| is_stream_id(s))?;
            let blob = string(fields, "blob").filter(|b| is_handle(b))?;
            let versions = read_versions(fields);
            Kind::File {
                stream,
                size: count(fields, "size"),
                media_type: string(fields, "type").filter(|t| is_media_type(t)),
                heads: heads(&blob, &versions),
                versions,
                blob,
            }
        }
        DOCUMENT_KIND => Kind::Document {
            stream: string(fields, "stream").filter(|s| is_stream_id(s))?,
            kind: string(fields, "docKind").filter(|k| is_kind_string(k))?,
        },
        _ => Kind::Other(kind_name),
    };
    let trashed = fields
        .get("trashed")
        .map(|_| count(fields, "trashed").unwrap_or(0));
    let meta = match value(fields, "meta") {
        Some(LoroValue::Map(map)) => map
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect(),
        _ => BTreeMap::new(),
    };
    Some(Entry {
        id,
        kind,
        name,
        parent: None,
        order: 0,
        added: count(fields, "added"),
        at: count(fields, "at"),
        trashed,
        meta,
        node,
    })
}

/// Whether the document's `document` map names the kind `frasil:drive`.
pub(crate) fn is_drive(doc: &LoroDoc) -> bool {
    string(&doc.get_map(DOCUMENT), "kind").as_deref() == Some(KIND)
}

impl Tree {
    /// Reads a drive whole (section 3.2).
    ///
    /// # Errors
    ///
    /// [`Error::NotADrive`].
    pub fn read(doc: &LoroDoc) -> Result<Self, Error> {
        if !is_drive(doc) {
            return Err(Error::NotADrive);
        }
        let tree = doc.get_tree(ENTRIES);
        let mut out = Tree::default();
        // Every node and its parent, readable or not.
        let mut stack: Vec<(TreeID, Option<TreeID>)> =
            tree.roots().into_iter().map(|id| (id, None)).collect();
        while let Some((node, parent)) = stack.pop() {
            out.node_parent.insert(node, parent);
            for child in tree.children(node).unwrap_or_default() {
                stack.push((child, Some(node)));
            }
        }
        // The walk: depth first, siblings in order.
        let mut walk: Vec<(TreeID, Option<usize>)> = tree
            .roots()
            .into_iter()
            .rev()
            .map(|id| (id, None))
            .collect();
        while let Some((node, parent)) = walk.pop() {
            let Ok(fields) = tree.get_meta(node) else {
                continue;
            };
            let Some(mut entry) = parse(&fields, node) else {
                continue;
            };
            if out.by_id.contains_key(&entry.id) {
                continue;
            }
            entry.parent = parent
                .map(|index| &out.entries[index])
                .filter(|holder| holder.kind.holds())
                .map(|holder| holder.id.clone());
            let index = out.entries.len();
            entry.order = index;
            out.by_id.insert(entry.id.clone(), index);
            out.by_node.insert(node, index);
            out.entries.push(entry);
            for child in tree.children(node).unwrap_or_default().into_iter().rev() {
                walk.push((child, Some(index)));
            }
        }
        if let LoroValue::Map(purged) = doc.get_map(PURGED).get_value() {
            out.purged = purged
                .iter()
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect();
        }
        Ok(out)
    }

    /// Every entry, in order, the trash's included.
    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    /// An entry by its ID.
    pub fn entry(&self, id: &str) -> Option<&Entry> {
        self.by_id.get(id).map(|&index| &self.entries[index])
    }

    /// Whether an entry is in the trash: it, or an entry above it, was
    /// trashed itself.
    pub fn in_trash(&self, entry: &Entry) -> bool {
        let mut at = Some(entry);
        while let Some(current) = at {
            if current.trashed.is_some() {
                return true;
            }
            at = current.parent.as_deref().and_then(|p| self.entry(p));
        }
        false
    }

    /// A folder's listing, or the root's for `None` (section 3.3): the
    /// entries in it not trashed themselves, in order, under shown names.
    pub fn listing(&self, folder: Option<&str>) -> Vec<Shown<'_>> {
        let items: Vec<&Entry> = self
            .entries
            .iter()
            .filter(|e| e.parent.as_deref() == folder && e.trashed.is_none())
            .collect();
        let names = shown_names(
            &items
                .iter()
                .map(|e| (e.name.as_str(), matches!(e.kind, Kind::File { .. })))
                .collect::<Vec<_>>(),
        );
        items
            .into_iter()
            .zip(names)
            .map(|(entry, name)| Shown { entry, name })
            .collect()
    }

    /// The trash: each entry trashed itself whose parent is not in the
    /// trash, the most recently trashed first, then in order.
    pub fn trash(&self) -> Vec<&Entry> {
        let mut items: Vec<&Entry> = self
            .entries
            .iter()
            .filter(|e| e.trashed.is_some())
            .filter(|e| {
                !e.parent
                    .as_deref()
                    .and_then(|p| self.entry(p))
                    .is_some_and(|p| self.in_trash(p))
            })
            .collect();
        items.sort_by_key(|e| (std::cmp::Reverse(e.trashed.unwrap_or(0)), e.order));
        items
    }

    /// A stream's entry: the first document entry that names it.
    pub fn stream_entry(&self, stream: &str) -> Option<&Entry> {
        self.entries
            .iter()
            .find(|e| matches!(&e.kind, Kind::Document { stream: s, .. } if s == stream))
    }

    /// Whether `purged` holds a stream.
    pub fn is_purged(&self, stream: &str) -> bool {
        self.purged.contains_key(stream)
    }

    /// Whether `node` is `top` or inside it in the tree.
    pub fn node_within(&self, node: TreeID, top: TreeID) -> bool {
        let mut at = Some(node);
        while let Some(current) = at {
            if current == top {
                return true;
            }
            at = self.node_parent.get(&current).copied().flatten();
        }
        false
    }

    /// The entries whose node is `top` or inside it, in order.
    pub fn entries_within(&self, top: TreeID) -> Vec<&Entry> {
        self.entries
            .iter()
            .filter(|e| self.node_within(e.node, top))
            .collect()
    }

    /// The files in conflict, in order (section 3.3).
    pub fn conflicts(&self) -> Vec<&Entry> {
        self.entries.iter().filter(|e| e.in_conflict()).collect()
    }

    /// The blobs, as stream and handle, that file entries whose nodes are
    /// `top` or inside it name, by `blob` or by a record, and no other entry
    /// names: what a purge of it releases. Sorted.
    pub fn released_by(&self, top: TreeID) -> Vec<(String, String)> {
        let kept: HashSet<(String, String)> = self
            .entries
            .iter()
            .filter(|e| !self.node_within(e.node, top))
            .flat_map(named_blobs)
            .collect();
        let mut released: Vec<(String, String)> = self
            .entries_within(top)
            .into_iter()
            .flat_map(named_blobs)
            .filter(|pair| !kept.contains(pair))
            .collect();
        released.sort();
        released.dedup();
        released
    }

    /// The entry of a node, if it is one.
    pub fn entry_of_node(&self, node: TreeID) -> Option<&Entry> {
        self.by_node.get(&node).map(|&index| &self.entries[index])
    }
}

/// The blobs an entry names, as stream and handle: a file's, by `blob` and
/// by its records.
fn named_blobs(entry: &Entry) -> Vec<(String, String)> {
    match &entry.kind {
        Kind::File {
            stream,
            blob,
            versions,
            ..
        } => std::iter::once((stream.clone(), blob.clone()))
            .chain(
                versions
                    .iter()
                    .map(|(handle, version)| (version.stream.clone(), handle.clone())),
            )
            .collect(),
        _ => Vec::new(),
    }
}

/// The tree parent for an entry's place: the root, or its node.
pub(crate) fn place(tree: &Tree, parent: Option<&str>) -> Result<TreeParentId, Error> {
    match parent {
        None => Ok(TreeParentId::Root),
        Some(id) => {
            let holder = tree.entry(id).ok_or(Error::NoSuchEntry)?;
            if holder.kind != Kind::Folder {
                return Err(Error::CannotHold);
            }
            Ok(TreeParentId::Node(holder.node))
        }
    }
}

/// `name` numbered `n` (section 3.3): before a file's last `.` when that is
/// not its first byte, else at the end.
pub fn numbered(name: &str, n: u64, is_file: bool) -> String {
    match name.rfind('.') {
        Some(dot) if is_file && dot > 0 => format!("{} ({n}){}", &name[..dot], &name[dot..]),
        _ => format!("{name} ({n})"),
    }
}

/// The shown names of a listing's entries, each given as its own name and
/// whether it is a file.
pub fn shown_names(items: &[(&str, bool)]) -> Vec<String> {
    let names: HashSet<&str> = items.iter().map(|(name, _)| *name).collect();
    let mut shown: HashSet<String> = HashSet::new();
    // The number each name tries next: every smaller one is taken, and
    // stays taken as `shown` only grows, so `k` entries of one name cost
    // `k` tries, not `k²`.
    let mut next: HashMap<(&str, bool), u64> = HashMap::new();
    let mut out = Vec::with_capacity(items.len());
    for &(own, is_file) in items {
        let mut name = own.to_owned();
        if shown.contains(&name) {
            let n = next.entry((own, is_file)).or_insert(2);
            loop {
                let candidate = numbered(own, *n, is_file);
                *n += 1;
                if !shown.contains(&candidate) && !names.contains(candidate.as_str()) {
                    name = candidate;
                    break;
                }
            }
        }
        shown.insert(name.clone());
        out.push(name);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(fields: &[(&str, LoroValue)]) -> LoroValue {
        let mut map: HashMap<String, LoroValue> = HashMap::from([
            ("stream".to_owned(), LoroValue::from("1".repeat(32))),
            ("parents".to_owned(), LoroValue::List(Vec::new().into())),
        ]);
        for (key, value) in fields {
            map.insert((*key).to_owned(), value.clone());
        }
        LoroValue::Map(map.into())
    }

    /// ext-drive.md, 2.4 Versions: a record not of the form reads as
    /// absent, a `size` or `at` of the wrong form included.
    #[test]
    fn a_record_with_an_optional_field_of_the_wrong_form_is_absent() {
        let handle = "2".repeat(32);
        let read = read_version(&handle, &record(&[("size", LoroValue::I64(3))])).unwrap();
        assert_eq!((read.size, read.at), (Some(3), None));
        assert!(read_version(&handle, &record(&[])).is_some());
        for key in ["size", "at"] {
            for wrong in [
                LoroValue::from("3"),
                LoroValue::I64(-1),
                LoroValue::Double(1.5),
                LoroValue::Null,
            ] {
                assert!(read_version(&handle, &record(&[(key, wrong)])).is_none());
            }
        }
    }
}
