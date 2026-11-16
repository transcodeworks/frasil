//! The schema: the tables a derive describes, their SQLite DDL, the JSON
//! manifest another language reads, and the version that names them.

use crate::index::column::{Column, ColumnKind, hex};
use crate::index::error::{Error, Result};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

/// The built-in columns of every table, before its own.
pub const BUILT_IN: [(&str, &str); 4] = [
    ("_space", "TEXT NOT NULL"),
    ("_key", "TEXT NOT NULL"),
    ("_author", "TEXT"),
    ("_changed_at", "INTEGER"),
];

/// The table of the spaces that feed the index.
pub const SPACES_TABLE: &str = "_spaces";

/// The manifest's format.
const FORMAT: u32 = 1;

/// A name read from a manifest, kept for the program's life, once.
fn intern(name: &str) -> &'static str {
    static NAMES: std::sync::Mutex<BTreeSet<&'static str>> = std::sync::Mutex::new(BTreeSet::new());
    let mut names = NAMES
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(found) = names.get(name) {
        return found;
    }
    let kept: &'static str = Box::leak(name.to_owned().into_boxed_str());
    names.insert(kept);
    kept
}

/// One column of a table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ColumnSchema {
    /// Its name, in Records and in SQL.
    pub name: &'static str,
    /// What it holds.
    pub kind: ColumnKind,
    /// Whether it may be absent.
    pub nullable: bool,
    /// The table whose keys it holds, for a reference.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub references: Option<&'static str>,
}

impl ColumnSchema {
    /// The column of a field of type `C`.
    pub const fn of<C: Column>(name: &'static str) -> Self {
        Self {
            name,
            kind: C::KIND,
            nullable: C::NULLABLE,
            references: C::REFERENCES,
        }
    }
}

/// One table: what `#[derive(Table)]` describes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct TableSchema {
    /// Its name, in Records and in SQL.
    pub name: &'static str,
    /// The kind of space that feeds it.
    pub source: &'static str,
    /// Whether it also holds open suggestions.
    pub suggestions: bool,
    /// Its own columns, after the built-in ones.
    pub columns: &'static [ColumnSchema],
}

impl TableSchema {
    /// Its SQLite DDL: the table, an index on `_key` and one on each
    /// reference.
    pub fn ddl(&self) -> String {
        let mut columns: Vec<String> = BUILT_IN
            .iter()
            .map(|(name, ty)| format!("\"{name}\" {ty}"))
            .collect();
        if self.suggestions {
            columns.push("\"_suggested\" INTEGER NOT NULL DEFAULT 0".into());
            columns.push("\"_suggestion\" TEXT NOT NULL DEFAULT ''".into());
        }
        for column in self.columns {
            let null = if column.nullable { "" } else { " NOT NULL" };
            columns.push(format!(
                "\"{}\" {}{null}",
                column.name,
                column.kind.sql_type()
            ));
        }
        let key = if self.suggestions {
            "\"_space\", \"_key\", \"_suggestion\""
        } else {
            "\"_space\", \"_key\""
        };
        let name = self.name;
        let mut ddl = format!(
            "CREATE TABLE \"{name}\" (\n  {},\n  PRIMARY KEY ({key})\n) WITHOUT ROWID;\n\
             CREATE INDEX \"{name}__key\" ON \"{name}\" (\"_key\");\n",
            columns.join(",\n  ")
        );
        for column in self.columns.iter().filter(|c| c.references.is_some()) {
            ddl.push_str(&format!(
                "CREATE INDEX \"{name}__{0}\" ON \"{name}\" (\"{0}\");\n",
                column.name
            ));
        }
        ddl
    }

    /// Its columns' names in SQL, built-in ones first.
    pub(crate) fn sql_columns(&self) -> Vec<&'static str> {
        let mut names: Vec<&'static str> = BUILT_IN.iter().map(|(name, _)| *name).collect();
        if self.suggestions {
            names.extend(["_suggested", "_suggestion"]);
        }
        names.extend(self.columns.iter().map(|c| c.name));
        names
    }
}

/// The tables of one index.
#[derive(Debug, Clone, Default)]
pub struct Schema {
    tables: Vec<TableSchema>,
}

#[derive(Serialize)]
struct Manifest<'a> {
    format: u32,
    built_in: Vec<BuiltIn>,
    spaces: Vec<BuiltIn>,
    tables: &'a [TableSchema],
}

#[derive(Serialize)]
struct BuiltIn {
    name: &'static str,
    sql: &'static str,
}

/// The `_spaces` table: each space that feeds the index, its kind, when
/// its cached content last changed, and who made it.
const SPACES_DDL: &str = "CREATE TABLE \"_spaces\" (\n  \
     \"id\" TEXT PRIMARY KEY NOT NULL,\n  \
     \"kind\" TEXT NOT NULL,\n  \
     \"synced_at\" INTEGER NOT NULL,\n  \
     \"owner\" TEXT\n);\n";

const SPACES_COLUMNS: [(&str, &str); 4] = [
    ("id", "TEXT PRIMARY KEY NOT NULL"),
    ("kind", "TEXT NOT NULL"),
    ("synced_at", "INTEGER NOT NULL"),
    ("owner", "TEXT"),
];

impl Schema {
    /// An empty schema.
    pub fn new() -> Self {
        Self::default()
    }

    /// The schema with table `T` too.
    #[must_use]
    pub fn table<T: crate::index::Table>(mut self) -> Self {
        self.tables.push(T::SCHEMA);
        self
    }

    /// The schema with a table described by hand.
    #[must_use]
    pub fn with(mut self, table: TableSchema) -> Self {
        self.tables.push(table);
        self
    }

    /// Its tables.
    pub fn tables(&self) -> &[TableSchema] {
        &self.tables
    }

    /// The tables a kind of space feeds.
    pub fn fed_by<'a>(&'a self, kind: &'a str) -> impl Iterator<Item = &'a TableSchema> + 'a {
        self.tables.iter().filter(move |t| t.source == kind)
    }

    /// A table by name.
    pub fn get(&self, name: &str) -> Option<&TableSchema> {
        self.tables.iter().find(|t| t.name == name)
    }

    /// Checks that the schema holds together: names are valid and unique,
    /// none is the index's own, and every reference names a table of it.
    ///
    /// # Errors
    ///
    /// [`Error::Schema`].
    pub fn check(&self) -> Result<()> {
        let mut names = BTreeSet::new();
        for table in &self.tables {
            valid_name(table.name)?;
            if table.source.is_empty() {
                return Err(Error::Schema(format!("{} has no source", table.name)));
            }
            if !names.insert(table.name) {
                return Err(Error::Schema(format!(
                    "two tables are named {}",
                    table.name
                )));
            }
            let mut columns = BTreeSet::new();
            if table.columns.is_empty() {
                return Err(Error::Schema(format!("{} has no column", table.name)));
            }
            for column in table.columns {
                valid_name(column.name)?;
                if !columns.insert(column.name) {
                    return Err(Error::Schema(format!(
                        "{} has two columns named {}",
                        table.name, column.name
                    )));
                }
            }
        }
        for table in &self.tables {
            for column in table.columns {
                if let Some(target) = column.references
                    && !names.contains(target)
                {
                    return Err(Error::Schema(format!(
                        "{}.{} names table {target}, which the schema lacks",
                        table.name, column.name
                    )));
                }
            }
        }
        Ok(())
    }

    /// The manifest: the schema as JSON, for an index in another language
    /// to read the same tables.
    pub fn manifest(&self) -> String {
        let built_in = |columns: &[(&'static str, &'static str)]| {
            columns
                .iter()
                .map(|(name, sql)| BuiltIn { name, sql })
                .collect()
        };
        serde_json::to_string(&Manifest {
            format: FORMAT,
            built_in: built_in(&BUILT_IN),
            spaces: built_in(&SPACES_COLUMNS),
            tables: &self.tables,
        })
        .expect("the manifest serialises")
    }

    /// A schema read back from its [manifest](Schema::manifest), for an
    /// index whose tables another language describes, such as the npm
    /// package's. The names it holds live as long as the program: read a
    /// manifest once, not once per query.
    ///
    /// # Errors
    ///
    /// [`Error::Schema`] when it is not a manifest of this format, or does
    /// not hold together ([`Schema::check`]).
    pub fn from_manifest(manifest: &str) -> Result<Self> {
        let bad = |what: &str| Error::Schema(format!("the manifest {what}"));
        let value: serde_json::Value =
            serde_json::from_str(manifest).map_err(|_| bad("is not JSON"))?;
        if value.get("format").and_then(serde_json::Value::as_u64) != Some(u64::from(FORMAT)) {
            return Err(bad(&format!("is not of format {FORMAT}")));
        }
        let text = |value: &serde_json::Value, field: &str| -> Result<&'static str> {
            value
                .get(field)
                .and_then(serde_json::Value::as_str)
                .map(intern)
                .ok_or_else(|| bad(&format!("lacks a {field}")))
        };
        let flag = |value: &serde_json::Value, field: &str| {
            value
                .get(field)
                .and_then(serde_json::Value::as_bool)
                .ok_or_else(|| bad(&format!("lacks {field}")))
        };
        let mut schema = Self::new();
        for table in value
            .get("tables")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| bad("lacks tables"))?
        {
            let mut columns = Vec::new();
            for column in table
                .get("columns")
                .and_then(serde_json::Value::as_array)
                .ok_or_else(|| bad("lacks a table's columns"))?
            {
                let kind = column
                    .get("kind")
                    .cloned()
                    .and_then(|kind| serde_json::from_value::<ColumnKind>(kind).ok())
                    .ok_or_else(|| bad("names a column kind it does not know"))?;
                columns.push(ColumnSchema {
                    name: text(column, "name")?,
                    kind,
                    nullable: flag(column, "nullable")?,
                    references: match column.get("references") {
                        None | Some(serde_json::Value::Null) => None,
                        Some(_) => Some(text(column, "references")?),
                    },
                });
            }
            schema = schema.with(TableSchema {
                name: text(table, "name")?,
                source: text(table, "source")?,
                suggestions: flag(table, "suggestions")?,
                columns: Box::leak(columns.into_boxed_slice()),
            });
        }
        schema.check()?;
        Ok(schema)
    }

    /// The schema's version: SHA-256 of its manifest, in hexadecimal. A
    /// cache of another version is rebuilt.
    pub fn version(&self) -> String {
        hex(&Sha256::digest(self.manifest().as_bytes()))
    }

    /// The DDL of every table, `_spaces` first.
    pub fn ddl(&self) -> String {
        let mut ddl = SPACES_DDL.to_owned();
        for table in &self.tables {
            ddl.push_str(&table.ddl());
        }
        ddl
    }
}

fn valid_name(name: &str) -> Result<()> {
    let mut chars = name.chars();
    let starts = chars.next().is_some_and(|c| c.is_ascii_lowercase());
    if starts && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_') {
        Ok(())
    } else {
        Err(Error::Schema(format!(
            "{name:?} is not lowercase ASCII letters, digits and `_` starting with a letter"
        )))
    }
}
