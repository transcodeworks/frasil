//! The index's errors.

/// What went wrong.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// Frasil's own error.
    Frasil(crate::Error),
    /// SQLite's error, with its message. A write through the query
    /// connection ends here too.
    Sql(String),
    /// The schema does not hold together: two tables of one name, a name
    /// the index keeps for itself, a reference to a table it lacks.
    Schema(String),
    /// A cached value is not of its field's type.
    Decode {
        /// The table.
        table: String,
        /// The column.
        column: String,
        /// What it should be.
        expected: &'static str,
    },
    /// A row lacks a column.
    NoColumn(String),
    /// The space is not a source: it was not made by [`create_space`] and
    /// has no kind.
    ///
    /// [`create_space`]: crate::index::create_space
    NoKind,
    /// The platform gave no randomness.
    NoRandomness,
    /// The index is closed, or its connection was poisoned by a panic.
    Closed,
}

impl Error {
    /// The error, naming the table and column it is about.
    #[must_use]
    pub fn in_column(self, table: &str, column: &str) -> Self {
        match self {
            Self::Decode { expected, .. } => Self::Decode {
                table: table.to_owned(),
                column: column.to_owned(),
                expected,
            },
            other => other,
        }
    }
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Frasil(error) => write!(f, "{error}"),
            Self::Sql(message) => write!(f, "SQLite: {message}"),
            Self::Schema(message) => write!(f, "schema: {message}"),
            Self::Decode {
                table,
                column,
                expected,
            } => write!(f, "{table}.{column} is not {expected}"),
            Self::NoColumn(column) => write!(f, "the row has no column {column}"),
            Self::NoKind => f.write_str("the space has no kind"),
            Self::NoRandomness => f.write_str("the platform gave no randomness"),
            Self::Closed => f.write_str("the index is closed"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Frasil(error) => Some(error),
            _ => None,
        }
    }
}

impl From<crate::Error> for Error {
    fn from(error: crate::Error) -> Self {
        Self::Frasil(error)
    }
}

impl From<rusqlite::Error> for Error {
    fn from(error: rusqlite::Error) -> Self {
        Self::Sql(error.to_string())
    }
}

/// The index's results.
pub type Result<T, E = Error> = core::result::Result<T, E>;
