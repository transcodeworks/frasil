//! `frasil::Error` as a JavaScript `Error` named `FrasilError`.
//!
//! Every error carries three fields besides its message:
//!
//! - `code`, stable. For a check of the specification that failed, it is
//!   the class in snake case, as the wire writes it (overview.md, "Error
//!   classes"). For the client's own failures it is the variant's name in
//!   snake case: `store`, `conflict`, `no_randomness`, `unknown_space`,
//!   `unknown_stream`, `not_allowed`, `sync_before_writing`,
//!   `rotation_due`, `adapter`, `connection`, `timeout`, `limit_passed`,
//!   `unsupported`, `released`, `incompatible_data`, `other_revision`; and
//!   `invalid_input` for an argument that does not read. `unknown` is a variant added to `frasil::Error` after this
//!   binding was written.
//! - `class`, for a failed check of the specification: the class as the
//!   specification names it, such as `Malformed`.
//! - `whatToDo`: `frasil::Error::what_to_do`, a sentence an application can
//!   show or log.

use frasil::Error;
use frasil_base::errors::snake_case;
use js_sys::Reflect;
use wasm_bindgen::JsValue;

/// The name every error this binding throws carries.
const NAME: &str = "FrasilError";

/// The stable code of an error.
pub fn code(error: &Error) -> String {
    match error {
        Error::Class(name) => snake_case(name),
        Error::Store(_) => "store".into(),
        Error::Conflict => "conflict".into(),
        Error::NoRandomness => "no_randomness".into(),
        Error::UnknownSpace => "unknown_space".into(),
        Error::UnknownStream => "unknown_stream".into(),
        Error::NotAllowed(_) => "not_allowed".into(),
        Error::SyncBeforeWriting => "sync_before_writing".into(),
        Error::RotationDue => "rotation_due".into(),
        Error::Adapter(_) => "adapter".into(),
        Error::Connection(_) => "connection".into(),
        Error::Timeout => "timeout".into(),
        Error::Delayed(_) => "delayed".into(),
        Error::LimitPassed => "limit_passed".into(),
        Error::Invalid(_) => "invalid_input".into(),
        Error::Unsupported(_) => "unsupported".into(),
        Error::Released => "released".into(),
        Error::IncompatibleData => "incompatible_data".into(),
        Error::OtherRevision => "other_revision".into(),
        Error::NeedsLaterVersion => "needs_later_version".into(),
        _ => "unknown".into(),
    }
}

/// `error` as the value JavaScript receives.
pub(crate) fn error(error: Error) -> JsValue {
    let class = error.class_name().map(JsValue::from_str);
    with_code(&code(&error), &error.to_string(), error.what_to_do(), class)
}

/// An error with this code, message, advice and class.
fn with_code(code: &str, message: &str, what_to_do: &str, class: Option<JsValue>) -> JsValue {
    let error = js_sys::Error::new(message);
    error.set_name(NAME);
    // Defining properties on a fresh `Error` cannot fail.
    let _ = Reflect::set(&error, &"code".into(), &code.into());
    let _ = Reflect::set(&error, &"whatToDo".into(), &what_to_do.into());
    if let Some(class) = class {
        let _ = Reflect::set(&error, &"class".into(), &class);
    }
    error.into()
}

/// An index's error as the value JavaScript receives: Frasil's own as
/// [`error`] gives them, the others under `index`.
#[cfg(feature = "index")]
pub(crate) fn index_error(failure: frasil::index::Error) -> JsValue {
    match failure {
        frasil::index::Error::Frasil(inner) => error(inner),
        other => with_code(
            "index",
            &other.to_string(),
            "Check the query or the schema; the index rebuilds from the device's replicas.",
            None,
        ),
    }
}

/// Converts `frasil`'s results for JavaScript with `?`.
pub(crate) trait Js<T> {
    /// The result, with the error converted.
    fn js(self) -> Result<T, JsValue>;
}

impl<T> Js<T> for frasil::Result<T> {
    fn js(self) -> Result<T, JsValue> {
        self.map_err(error)
    }
}

/// An argument JavaScript passed that does not convert: `invalid_input`.
pub(crate) fn invalid(message: &str) -> JsValue {
    with_code(
        "invalid_input",
        message,
        Error::Invalid("").what_to_do(),
        None,
    )
}
