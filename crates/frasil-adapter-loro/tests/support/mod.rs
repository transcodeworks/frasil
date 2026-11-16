//! A small Loro replica for tests: a tree of titled text nodes in a Loro
//! document, written under a bound peer, whose units carry real Loro
//! bytes.

#![allow(dead_code)]

pub mod crafted;
pub mod crafted_snapshot;

use frasil_adapter::{Capabilities, Context, EventId, Role, StreamUnit};
use frasil_adapter_loro::write::Writer;
use frasil_adapter_loro::{Content, Incarnation};
use loro::{LoroDoc, LoroText, TreeID, TreeParentId, UpdateOptions};

/// The space every test unit is in.
pub const SPACE: [u8; 32] = [0x5a; 32];
/// The stream every test unit is in.
pub const STREAM: [u8; 16] = [0x57; 16];

/// Why a replica refused an operation.
pub type Error = Box<dyn std::error::Error + Send + Sync>;
/// Result of a replica operation.
pub type Result<T> = std::result::Result<T, Error>;

/// Identity of a node, stable across renames and moves.
pub type NodeId = TreeID;

const TREE: &str = "nodes";
const TITLE: &str = "title";
const BODY: &str = "body";

/// One node as a replica sees it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Node {
    /// The node's identity.
    pub id: NodeId,
    /// The node it sits under, if any.
    pub parent: Option<NodeId>,
    /// Its title; the last rename wins.
    pub title: String,
    /// Its text; concurrent edits merge.
    pub body: String,
}

/// A writer's replica: a document and the incarnation it writes under.
pub struct Replica {
    doc: LoroDoc,
    writer: Writer,
}

/// The incarnation `s` of `author` in the test stream.
pub fn incarnation(author: u8, s: u64) -> Incarnation {
    Incarnation {
        space: SPACE,
        stream: STREAM,
        author: [author; 32],
        incarnation: s,
    }
}

impl Replica {
    /// An empty replica writing under `author`'s incarnation `s`.
    pub fn new(author: u8, s: u64) -> Self {
        Self::over(LoroDoc::new(), author, s)
    }

    /// A replica forked from a document, such as a stream's main document,
    /// writing under `author`'s incarnation `s`.
    pub fn from_doc(doc: &LoroDoc, author: u8, s: u64) -> Self {
        Self::over(doc.fork(), author, s)
    }

    fn over(doc: LoroDoc, author: u8, s: u64) -> Self {
        let writer = Writer::new(&doc, incarnation(author, s)).unwrap();
        Self { doc, writer }
    }

    /// The replica's document.
    pub fn doc(&self) -> &LoroDoc {
        &self.doc
    }

    /// Merges another replica's operations.
    pub fn import(&mut self, bytes: &[u8]) -> Result<()> {
        self.doc.import(bytes)?;
        Ok(())
    }

    /// The operations written since the last unit, as an edit.
    pub fn edit_unit(&mut self) -> Content {
        self.writer.edit(&self.doc).unwrap().expect("operations")
    }

    /// The operations written since the last unit, as a suggestion.
    pub fn suggestion_unit(&mut self) -> Content {
        self.writer
            .suggestion(&self.doc)
            .unwrap()
            .expect("operations")
    }

    /// Add a node, optionally under another.
    pub fn create(&mut self, title: &str, parent: Option<NodeId>) -> Result<NodeId> {
        let tree = self.doc.get_tree(TREE);
        let id = tree.create(parent)?;
        let meta = tree.get_meta(id)?;
        meta.insert(TITLE, title)?;
        meta.insert_container(BODY, LoroText::new())?;
        self.doc.commit();
        Ok(id)
    }

    /// Give a node another title.
    pub fn rename(&mut self, id: NodeId, title: &str) -> Result<()> {
        self.doc.get_tree(TREE).get_meta(id)?.insert(TITLE, title)?;
        self.doc.commit();
        Ok(())
    }

    /// Replace a node's text, recorded as the difference from what it held.
    pub fn edit(&mut self, id: NodeId, text: &str) -> Result<()> {
        let body = self
            .doc
            .get_tree(TREE)
            .get_meta(id)?
            .get(BODY)
            .and_then(|value| value.into_container().ok())
            .and_then(|container| container.into_text().ok())
            .ok_or_else(|| format!("node {id} has no text"))?;
        body.update(text, UpdateOptions::default())
            .map_err(|error| format!("text update: {error:?}"))?;
        self.doc.commit();
        Ok(())
    }

    /// Move a node under another, or to the top with `None`.
    pub fn move_note(&mut self, id: NodeId, parent: Option<NodeId>) -> Result<()> {
        self.doc.get_tree(TREE).mov(id, parent)?;
        self.doc.commit();
        Ok(())
    }
}

/// Every node of a document, ordered by identity so equal documents
/// compare equal.
pub fn notes(doc: &LoroDoc) -> Vec<Node> {
    let tree = doc.get_tree(TREE);
    let mut nodes = Vec::new();
    for node in tree.get_nodes(false) {
        let meta = tree.get_meta(node.id).unwrap();
        let title = meta
            .get(TITLE)
            .and_then(|value| value.into_value().ok())
            .and_then(|value| value.into_string().ok())
            .map(|title| title.to_string())
            .unwrap_or_default();
        let body = meta
            .get(BODY)
            .and_then(|value| value.into_container().ok())
            .and_then(|container| container.into_text().ok())
            .map(|text| text.to_string())
            .unwrap_or_default();
        let parent = match node.parent {
            TreeParentId::Node(parent) => Some(parent),
            _ => None,
        };
        nodes.push(Node {
            id: node.id,
            parent,
            title,
            body,
        });
    }
    nodes.sort_by_key(|node| node.id);
    nodes
}

/// One node of a document.
pub fn note(doc: &LoroDoc, id: NodeId) -> Node {
    notes(doc).into_iter().find(|node| node.id == id).unwrap()
}

/// A log unit of `author` at `seq`, named `id`, valid by the write rule.
pub fn unit(id: u8, author: u8, seq: u64, content: &Content) -> StreamUnit {
    unit_with(id, author, seq, content, Capabilities::none(), true)
}

/// A log unit with capabilities and a write-rule verdict.
pub fn unit_with(
    id: u8,
    author: u8,
    seq: u64,
    content: &Content,
    capabilities: Capabilities,
    valid: bool,
) -> StreamUnit {
    StreamUnit {
        context: Context::new(SPACE, STREAM, event(id), [author; 32], seq, seq, Role::Log)
            .with_capabilities(capabilities),
        content: content.encode(),
        valid,
    }
}

/// The event ID named by `id`.
pub fn event(id: u8) -> EventId {
    [id; 32]
}
