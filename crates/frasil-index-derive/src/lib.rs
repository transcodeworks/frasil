//! `#[derive(Table)]` for the `index` feature of `frasil`: a plain struct with named fields
//! becomes one table of the index.
//!
//! ```ignore
//! #[derive(Table)]
//! #[table(source = "shared", name = "items", suggestions)]
//! struct Item {
//!     list: Ref<List>,
//!     #[column(name = "label")]
//!     title: String,
//!     done: bool,
//! }
//! ```
//!
//! - `source` (required): the kind of space whose Records feed the table.
//! - `name`: the table's name in Records and in SQL; the struct's name in
//!   snake case by default.
//! - `suggestions`: the table also holds open suggestions, one row per
//!   suggestion and row, marked by `_suggested`.
//! - `#[column(name = "…")]` on a field: the column's name, the field's by
//!   default.
//!
//! The macro implements `frasil::index::Table`: the table's schema, its
//! cells for a Records write, and a struct from a cached row. With the
//! `diesel` feature (`frasil`'s `index-diesel`) it also emits a Diesel `table!` module named after the
//! table. `#[table(no_diesel)]` opts a table out when another dependency
//! enables the feature through Cargo feature unification.

use proc_macro::TokenStream;
use proc_macro2::{Span, TokenStream as Tokens};
use quote::quote;
use syn::{Data, DeriveInput, Fields, Ident, LitStr, parse_macro_input};

/// Derives `frasil::index::Table` for a struct with named fields.
#[proc_macro_derive(Table, attributes(table, column))]
pub fn derive_table(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    match expand(&input) {
        Ok(tokens) => tokens.into(),
        Err(error) => error.to_compile_error().into(),
    }
}

/// The `#[table(…)]` arguments.
struct TableArgs {
    source: LitStr,
    name: LitStr,
    suggestions: bool,
    no_diesel: bool,
}

/// One field and its column.
struct Field {
    ident: Ident,
    ty: syn::Type,
    column: LitStr,
}

fn expand(input: &DeriveInput) -> syn::Result<Tokens> {
    if !input.generics.params.is_empty() {
        return Err(syn::Error::new_spanned(
            &input.generics,
            "a table is a struct without generic parameters",
        ));
    }
    let args = table_args(input)?;
    let fields = fields(input)?;
    let ident = &input.ident;
    let TableArgs {
        source,
        name,
        suggestions,
        ..
    } = &args;

    let schema_columns = fields.iter().map(|f| {
        let ty = &f.ty;
        let column = &f.column;
        quote! { ::frasil::index::ColumnSchema::of::<#ty>(#column) }
    });
    let cells = fields.iter().map(|f| {
        let field = &f.ident;
        let column = &f.column;
        quote! { (#column, ::frasil::index::Column::to_cell(&self.#field)) }
    });
    let reads = fields.iter().map(|f| {
        let field = &f.ident;
        let column = &f.column;
        quote! {
            #field: ::frasil::index::Column::from_sql(row.get(#column)?)
                .map_err(|error| error.in_column(#name, #column))?
        }
    });

    let diesel = diesel_table(input, &args, &fields)?;

    Ok(quote! {
        impl ::frasil::index::Table for #ident {
            const SCHEMA: ::frasil::index::TableSchema = ::frasil::index::TableSchema {
                name: #name,
                source: #source,
                suggestions: #suggestions,
                columns: &[#(#schema_columns),*],
            };

            fn cells(&self) -> ::std::vec::Vec<(&'static str, ::frasil::index::Cell)> {
                ::std::vec![#(#cells),*]
            }

            fn from_row(row: &::frasil::index::Row) -> ::frasil::index::Result<Self> {
                ::core::result::Result::Ok(Self { #(#reads),* })
            }
        }

        #diesel
    })
}

fn table_args(input: &DeriveInput) -> syn::Result<TableArgs> {
    let mut source = None;
    let mut name = None;
    let mut suggestions = false;
    let mut no_diesel = false;
    for attr in input.attrs.iter().filter(|a| a.path().is_ident("table")) {
        attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("source") {
                source = Some(meta.value()?.parse::<LitStr>()?);
            } else if meta.path.is_ident("name") {
                name = Some(meta.value()?.parse::<LitStr>()?);
            } else if meta.path.is_ident("suggestions") {
                suggestions = true;
            } else if meta.path.is_ident("no_diesel") {
                no_diesel = true;
            } else {
                return Err(meta.error("expected `source`, `name`, `suggestions` or `no_diesel`"));
            }
            Ok(())
        })?;
    }
    let source = source.ok_or_else(|| {
        syn::Error::new_spanned(
            &input.ident,
            "a table names its source: #[table(source = \"kind\")]",
        )
    })?;
    if source.value().is_empty() {
        return Err(syn::Error::new_spanned(&source, "a source is not empty"));
    }
    let name = name
        .unwrap_or_else(|| LitStr::new(&snake_case(&input.ident.to_string()), Span::call_site()));
    check_name(&name)?;
    Ok(TableArgs {
        source,
        name,
        suggestions,
        no_diesel,
    })
}

fn fields(input: &DeriveInput) -> syn::Result<Vec<Field>> {
    let Data::Struct(data) = &input.data else {
        return Err(syn::Error::new_spanned(
            &input.ident,
            "a table is a struct with named fields",
        ));
    };
    let Fields::Named(named) = &data.fields else {
        return Err(syn::Error::new_spanned(
            &input.ident,
            "a table is a struct with named fields",
        ));
    };
    let mut out = Vec::new();
    for field in &named.named {
        let ident = field.ident.clone().expect("a named field");
        let mut column = None;
        for attr in field.attrs.iter().filter(|a| a.path().is_ident("column")) {
            attr.parse_nested_meta(|meta| {
                if meta.path.is_ident("name") {
                    column = Some(meta.value()?.parse::<LitStr>()?);
                    Ok(())
                } else {
                    Err(meta.error("expected `name`"))
                }
            })?;
        }
        let column = column.unwrap_or_else(|| {
            let text = ident.to_string();
            LitStr::new(text.strip_prefix("r#").unwrap_or(&text), ident.span())
        });
        check_name(&column)?;
        out.push(Field {
            ident,
            ty: field.ty.clone(),
            column,
        });
    }
    if out.is_empty() {
        return Err(syn::Error::new_spanned(
            &input.ident,
            "a table has at least one column",
        ));
    }
    Ok(out)
}

/// Names of tables and columns: lowercase ASCII letters, digits and `_`,
/// starting with a letter. A leading `_` is the index's own.
fn check_name(name: &LitStr) -> syn::Result<()> {
    let text = name.value();
    let mut chars = text.chars();
    let starts = chars.next().is_some_and(|c| c.is_ascii_lowercase());
    if starts && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_') {
        Ok(())
    } else {
        Err(syn::Error::new_spanned(
            name,
            "a name is lowercase ASCII letters, digits and `_`, and starts with a letter",
        ))
    }
}

fn snake_case(name: &str) -> String {
    let mut out = String::new();
    for (i, c) in name.chars().enumerate() {
        if c.is_ascii_uppercase() {
            if i > 0 {
                out.push('_');
            }
            out.push(c.to_ascii_lowercase());
        } else {
            out.push(c);
        }
    }
    out
}

#[cfg(feature = "diesel")]
fn diesel_table(_: &DeriveInput, args: &TableArgs, fields: &[Field]) -> syn::Result<Tokens> {
    if args.no_diesel {
        return Ok(Tokens::new());
    }
    let table = Ident::new(&args.name.value(), args.name.span());
    let mut columns = Vec::new();
    for field in fields {
        let column = Ident::new(&field.column.value(), field.column.span());
        let sql = diesel_type(&field.ty)?;
        let doc = format!("The `{}` column.", field.column.value());
        columns.push(quote! { #[doc = #doc] #column -> #sql, });
    }
    let (key, suggested) = if args.suggestions {
        (
            quote! { (_space, _key, _suggestion) },
            quote! {
                #[doc = "1 for a row as an open suggestion would make it."]
                _suggested -> Bool,
                #[doc = "The open suggestion's ID; empty for a merged row."]
                _suggestion -> Text,
            },
        )
    } else {
        (quote! { (_space, _key) }, quote! {})
    };
    let doc = format!(
        "The `{}` table of the index, for Diesel.",
        args.name.value()
    );
    Ok(quote! {
        ::diesel::table! {
            use ::diesel::sql_types::*;

            #[doc = #doc]
            #table #key {
                #[doc = "The space that holds the row."]
                _space -> Text,
                #[doc = "The row's key, in hexadecimal."]
                _key -> Text,
                #[doc = "Who last changed the row."]
                _author -> Nullable<Text>,
                #[doc = "When, by the writer's clock, in milliseconds."]
                _changed_at -> Nullable<BigInt>,
                #suggested
                #(#columns)*
            }
        }
    })
}

/// A field type's Diesel SQL type, by the name of its last path segment:
/// the column types frasil-index defines.
#[cfg(feature = "diesel")]
fn diesel_type(ty: &syn::Type) -> syn::Result<Tokens> {
    let unknown = || {
        syn::Error::new_spanned(
            ty,
            "a column is i64, f64, bool, String, Vec<u8>, Time, Ref<T>, RichText or an Option of one",
        )
    };
    let syn::Type::Path(path) = ty else {
        return Err(unknown());
    };
    let last = path.path.segments.last().ok_or_else(unknown)?;
    let inner = || match &last.arguments {
        syn::PathArguments::AngleBracketed(args) => match args.args.first() {
            Some(syn::GenericArgument::Type(inner)) if args.args.len() == 1 => Ok(inner),
            _ => Err(unknown()),
        },
        _ => Err(unknown()),
    };
    Ok(match last.ident.to_string().as_str() {
        "i64" | "Time" => quote! { BigInt },
        "f64" => quote! { Double },
        "bool" => quote! { Bool },
        "String" | "Ref" | "RichText" => quote! { Text },
        "Vec" => match inner()? {
            syn::Type::Path(p) if p.path.is_ident("u8") => quote! { Binary },
            _ => return Err(unknown()),
        },
        "Option" => {
            let inner = diesel_type(inner()?)?;
            quote! { Nullable<#inner> }
        }
        _ => return Err(unknown()),
    })
}

#[cfg(not(feature = "diesel"))]
fn diesel_table(_: &DeriveInput, args: &TableArgs, _: &[Field]) -> syn::Result<Tokens> {
    let _ = args.no_diesel;
    Ok(Tokens::new())
}
