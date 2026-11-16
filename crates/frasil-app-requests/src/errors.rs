//! Error classes and the codes a verifier answers (ext-app-requests.md,
//! "Error classes and codes").
//!
//! Every refusal is a decision about one request, so every class here is of
//! sort `Decision`. `Replayed` is overview.md's shared class. `WrongPerson`
//! is identity.md's class, which the verifier raises at step 9; identity.md's
//! `ForkDetected` is a report, which a list delivery carries in
//! [`crate::Placed::fork_detected`], never a refusal.

use frasil_base::ErrorClass;
use frasil_base::errors::Class;

frasil_base::error_classes! {
    /// The classes ext-app-requests.md defines, identity.md's `WrongPerson`,
    /// and every shared class.
    pub enum AppRequestClass {
        /// None of the headers is present.
        Unsigned = "unsigned", Decision;
        /// A list delivery that does not read, or holds an event that is not
        /// a list event of the person.
        BadListDelivery = "bad_list_delivery", Decision;
        /// The verifier holds no list of the person, or the heads name an
        /// event it has not placed, and its list does not hold the signer.
        ListNeeded = "list_needed", Decision;
        /// The verifier's merged list does not hold the key as a signer
        /// (ext-app-requests.md, "Who signs").
        NotASigner = "not_a_signer", Decision;
        /// identity.md's class: the subject's recorded person is another
        /// person.
        WrongPerson = "wrong_person", Decision;
    }
}

/// The status and code a verifier answers (ext-app-requests.md, "Error
/// classes and codes").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Code {
    /// 401 `unauthorized`: no bearer, a token refused, an inactive account.
    /// Told to anyone.
    Unauthorized,
    /// 401 `signature_required`: `Unsigned`.
    SignatureRequired,
    /// 401 `signature_invalid`: `Malformed`, `UnsupportedVersion`,
    /// `InvalidKey`, `BadSignature`, `Replayed`.
    SignatureInvalid,
    /// 401 `signature_expired`: `check_expiry`'s `Expired` or `Malformed`.
    SignatureExpired,
    /// 403 `device_not_listed`: `WrongPerson`, `NotASigner`.
    DeviceNotListed,
    /// 403 `device_list_needed`, with `X-Frasil-List-Needed: 1`:
    /// `ListNeeded`.
    DeviceListNeeded,
    /// 400 `malformed`: `BadListDelivery`.
    Malformed,
}

impl Code {
    /// The HTTP status.
    pub const fn status(self) -> u16 {
        match self {
            Code::Unauthorized
            | Code::SignatureRequired
            | Code::SignatureInvalid
            | Code::SignatureExpired => 401,
            Code::DeviceNotListed | Code::DeviceListNeeded => 403,
            Code::Malformed => 400,
        }
    }

    /// The code, as the answer carries it.
    pub const fn as_str(self) -> &'static str {
        match self {
            Code::Unauthorized => "unauthorized",
            Code::SignatureRequired => "signature_required",
            Code::SignatureInvalid => "signature_invalid",
            Code::SignatureExpired => "signature_expired",
            Code::DeviceNotListed => "device_not_listed",
            Code::DeviceListNeeded => "device_list_needed",
            Code::Malformed => "malformed",
        }
    }

    /// Whether the answer carries `X-Frasil-List-Needed: 1`.
    pub const fn asks_for_list(self) -> bool {
        matches!(self, Code::DeviceListNeeded)
    }

    /// The code of a class the verifier refuses with, outside step 7. One
    /// code covers every way a signature is wrong, so a caller without the
    /// key cannot learn which field it got wrong; a shared class the table
    /// does not name is answered as one.
    pub fn of(class: AppRequestClass) -> Self {
        match class {
            AppRequestClass::Unsigned => Code::SignatureRequired,
            AppRequestClass::WrongPerson | AppRequestClass::NotASigner => Code::DeviceNotListed,
            AppRequestClass::ListNeeded => Code::DeviceListNeeded,
            AppRequestClass::BadListDelivery => Code::Malformed,
            AppRequestClass::Shared(_) => Code::SignatureInvalid,
        }
    }
}

/// Why the verifier refused a request: a class of its steps, or step 7's
/// `check_expiry`, whose `Expired` and `Malformed` have a code of their own.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Refusal {
    /// A class of steps 3 to 6 or 8 to 11.
    Request(AppRequestClass),
    /// `check_expiry`'s class at step 7: `Expired` or `Malformed`.
    Expiry(ErrorClass),
}

impl Refusal {
    /// The class's UpperCamelCase name, such as `NotASigner`.
    pub fn name(self) -> &'static str {
        match self {
            Refusal::Request(class) => class.name(),
            Refusal::Expiry(class) => class.name(),
        }
    }

    /// The class.
    pub fn class(self) -> AppRequestClass {
        match self {
            Refusal::Request(class) => class,
            Refusal::Expiry(class) => AppRequestClass::Shared(class),
        }
    }

    /// The status and code the verifier answers.
    pub fn code(self) -> Code {
        match self {
            Refusal::Request(class) => Code::of(class),
            Refusal::Expiry(_) => Code::SignatureExpired,
        }
    }
}

impl From<AppRequestClass> for Refusal {
    fn from(class: AppRequestClass) -> Self {
        Refusal::Request(class)
    }
}

impl From<ErrorClass> for Refusal {
    fn from(class: ErrorClass) -> Self {
        Refusal::Request(AppRequestClass::Shared(class))
    }
}

impl core::fmt::Display for Refusal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.code().as_str())
    }
}

impl std::error::Error for Refusal {}

#[cfg(test)]
mod tests {
    use super::*;
    use frasil_base::errors::{Sort, snake_case};

    #[test]
    fn wire_names_are_snake_case() {
        for class in AppRequestClass::OWN {
            assert_eq!(class.wire_name(), snake_case(class.name()));
            assert_eq!(class.sort(), Sort::Decision);
            assert_eq!(AppRequestClass::from_name(class.name()), Some(*class));
        }
        assert_eq!(
            AppRequestClass::from_name("Replayed"),
            Some(AppRequestClass::Shared(ErrorClass::Replayed))
        );
    }

    #[test]
    fn an_expiry_has_its_own_code() {
        let expiry = Refusal::Expiry(ErrorClass::Malformed);
        let shape = Refusal::from(ErrorClass::Malformed);
        assert_eq!(expiry.code(), Code::SignatureExpired);
        assert_eq!(shape.code(), Code::SignatureInvalid);
        assert_eq!(expiry.name(), shape.name());
        assert!(
            Refusal::Request(AppRequestClass::ListNeeded)
                .code()
                .asks_for_list()
        );
    }
}
