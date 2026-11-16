//! Conversions between JavaScript values and `frasil`'s types. Each
//! function converts one shape into another and nothing more.
//!
//! - IDs cross as lowercase hexadecimal strings, as `frasil`'s IDs show
//!   and parse.
//! - Keys, signed events and other byte strings cross as `Uint8Array`s.
//! - Counts and sizes cross as `number`s; every one this binding hands out
//!   is far below 2^53.
//! - A Records cell's value (`frasil::Value`, the deterministic CBOR subset
//!   of overview.md, section 5.3) is a non-negative integer (`number`, or
//!   `bigint` from 2^53), a `Uint8Array`, a `string`, an array of values,
//!   or a `Map` from non-negative integers to values.
//! - A Loro value is `null`, a `boolean`, a `number` (or a `bigint` beyond
//!   2^53), a `string`, a `Uint8Array`, an array of values, or a plain
//!   object of values; a container shows as its ID's text.

use crate::error::{Js, invalid};
use frasil::Value;
use js_sys::{Array, ArrayBuffer, BigInt, Object, Reflect, Uint8Array};
use wasm_bindgen::{JsCast, JsValue};

/// The greatest integer a `number` holds exactly: 2^53 - 1.
const SAFE: u64 = (1 << 53) - 1;

/// The deepest nesting of a value this binding converts, as the
/// deterministic CBOR subset allows (overview.md, section 5.3).
const MAX_DEPTH: usize = frasil_base::cbor::MAX_DEPTH;

/// A plain JavaScript object under construction.
pub(crate) struct Obj(Object);

impl Obj {
    pub(crate) fn new() -> Self {
        Self(Object::new())
    }

    /// Sets `key`. Defining a property of a fresh plain object cannot fail.
    pub(crate) fn set(self, key: &str, value: impl Into<JsValue>) -> Self {
        let _ = Reflect::set(&self.0, &JsValue::from_str(key), &value.into());
        self
    }

    /// Defines `key` as an own data property, whatever its name: a key
    /// such as `__proto__` from another party's data stays a key.
    pub(crate) fn define(self, key: &str, value: &JsValue) -> Self {
        let descriptor = Obj::new()
            .set("value", value.clone())
            .set("enumerable", true)
            .set("writable", true)
            .set("configurable", true)
            .build();
        let _ =
            Reflect::define_property(&self.0, &JsValue::from_str(key), descriptor.unchecked_ref());
        self
    }

    pub(crate) fn build(self) -> JsValue {
        self.0.into()
    }
}

/// Bytes as a new `Uint8Array`.
pub(crate) fn bytes(value: &[u8]) -> JsValue {
    Uint8Array::from(value).into()
}

/// Bytes as lowercase hexadecimal, as `frasil`'s IDs show.
pub(crate) fn hex(value: &[u8]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// A count as a `number`.
pub(crate) fn number(value: usize) -> JsValue {
    JsValue::from_f64(value as f64)
}

/// A non-negative integer as a `number`, or a `bigint` from 2^53.
fn unsigned(value: u64) -> JsValue {
    if value <= SAFE {
        JsValue::from_f64(value as f64)
    } else {
        BigInt::from(value).into()
    }
}

/// A JavaScript array of converted items.
pub(crate) fn array<T>(
    items: impl IntoIterator<Item = T>,
    convert: impl Fn(T) -> JsValue,
) -> JsValue {
    let out = Array::new();
    for item in items {
        out.push(&convert(item));
    }
    out.into()
}

/// One property. A getter that throws gives its exception.
pub(crate) fn field(value: &JsValue, key: &str) -> Result<JsValue, JsValue> {
    Reflect::get(value, &JsValue::from_str(key))
}

/// A string property, or `invalid_input` naming `what`.
pub(crate) fn text_field(value: &JsValue, key: &str, what: &str) -> Result<String, JsValue> {
    field(value, key)?
        .as_string()
        .ok_or_else(|| invalid(&format!("{what}'s {key} is a string.")))
}

/// A non-negative integer property below 2^32, or `invalid_input`.
pub(crate) fn index_field(value: &JsValue, key: &str, what: &str) -> Result<usize, JsValue> {
    let number = field(value, key)?.as_f64();
    match number {
        Some(n) if n.is_finite() && n >= 0.0 && n.fract() == 0.0 && n <= f64::from(u32::MAX) => {
            Ok(n as usize)
        }
        _ => Err(invalid(&format!(
            "{what}'s {key} is a non-negative integer."
        ))),
    }
}

/// The bytes of a `Uint8Array` or `ArrayBuffer`; `None` for any other
/// value.
pub(crate) fn bytes_in(value: &JsValue) -> Option<Vec<u8>> {
    if let Some(array) = value.dyn_ref::<Uint8Array>() {
        return Some(array.to_vec());
    }
    value
        .dyn_ref::<ArrayBuffer>()
        .map(|buffer| Uint8Array::new(buffer).to_vec())
}

/// A key: a `Uint8Array`, or a string as its UTF-8 bytes.
pub(crate) fn key_in(value: &JsValue, what: &str) -> Result<Vec<u8>, JsValue> {
    if let Some(text) = value.as_string() {
        return Ok(text.into_bytes());
    }
    bytes_in(value).ok_or_else(|| invalid(&format!("{what} is a string or a Uint8Array.")))
}

/// Exactly `N` bytes from what JavaScript passed as `what`.
pub(crate) fn exact<const N: usize>(value: &[u8], what: &str) -> Result<[u8; N], JsValue> {
    value
        .try_into()
        .map_err(|_| invalid(&format!("{what} is exactly {N} bytes.")))
}

/// An ID from its hexadecimal text.
pub(crate) fn id<T: core::str::FromStr<Err = frasil::Error>>(text: &str) -> Result<T, JsValue> {
    text.parse::<T>().js()
}

/// The items of a JavaScript array, or `invalid_input` naming `what`.
pub(crate) fn items(value: &JsValue, what: &str) -> Result<Vec<JsValue>, JsValue> {
    value
        .dyn_ref::<Array>()
        .map(|array| array.iter().collect())
        .ok_or_else(|| invalid(&format!("{what} is an array.")))
}

/// An array of byte strings, from a JavaScript array of `Uint8Array`s.
pub(crate) fn byte_strings(value: &JsValue, what: &str) -> Result<Vec<Vec<u8>>, JsValue> {
    items(value, what)?
        .iter()
        .map(|item| {
            bytes_in(item).ok_or_else(|| invalid(&format!("{what} is an array of Uint8Array.")))
        })
        .collect()
}

/// A non-negative integer from a `number` or a `bigint`.
pub(crate) fn unsigned_in(value: &JsValue) -> Option<u64> {
    if let Some(n) = value.as_f64() {
        let exact = n.is_finite() && n >= 0.0 && n.fract() == 0.0 && n <= SAFE as f64;
        return exact.then_some(n as u64);
    }
    if value.is_bigint() {
        return u64::try_from(value.clone()).ok();
    }
    None
}

/// A negative integer, as the records subset holds it: `-1 - n` as
/// `Negative(n)`. A number must be an exact integer within 2^53.
fn negative_in(value: &JsValue) -> Option<Value> {
    if let Some(n) = value.as_f64() {
        let exact = n.is_finite() && n < 0.0 && n.fract() == 0.0 && -n <= SAFE as f64;
        return exact.then(|| Value::from(n as i64));
    }
    if value.is_bigint() {
        let n = i128::try_from(value.clone()).ok()?;
        // -1 - n, as two's complement.
        let magnitude = u64::try_from(!n).ok()?;
        return (n < 0).then_some(Value::Negative(magnitude));
    }
    None
}

/// A Records value from JavaScript.
pub(crate) fn value_in(value: &JsValue, depth: usize) -> Result<Value, JsValue> {
    const SHAPE: &str = "a value is an integer, a number, a boolean, a Uint8Array, a string, an \
                         array of values, or a Map from non-negative integers to values, nested at \
                         most 16 deep; a number is never NaN.";
    if depth > MAX_DEPTH {
        return Err(invalid(SHAPE));
    }
    let deeper = depth.saturating_add(1);
    if let Some(text) = value.as_string() {
        return Ok(Value::Text(text));
    }
    if let Some(n) = unsigned_in(value) {
        return Ok(Value::Unsigned(n));
    }
    if let Some(negative) = negative_in(value) {
        return Ok(negative);
    }
    if let Some(b) = value.as_bool() {
        return Ok(Value::Bool(b));
    }
    // Any other number is a binary64 float: one with a fraction, or an
    // integer beyond 2^53.
    if let Some(n) = value.as_f64() {
        if n.is_nan() {
            return Err(invalid(SHAPE));
        }
        return Ok(Value::Float(n));
    }
    if let Some(bytes) = bytes_in(value) {
        return Ok(Value::Bytes(bytes));
    }
    if let Some(array) = value.dyn_ref::<Array>() {
        return array
            .iter()
            .map(|item| value_in(&item, deeper))
            .collect::<Result<Vec<_>, _>>()
            .map(Value::Array);
    }
    if let Some(map) = value.dyn_ref::<js_sys::Map>() {
        let mut out = frasil_base::cbor::Map::new();
        let mut failed = None;
        map.for_each(&mut |item, key| {
            if failed.is_some() {
                return;
            }
            match (unsigned_in(&key), value_in(&item, deeper)) {
                (Some(key), Ok(item)) => {
                    out.insert(key, item);
                }
                (_, Err(why)) => failed = Some(why),
                (None, _) => failed = Some(invalid(SHAPE)),
            }
        });
        return match failed {
            Some(why) => Err(why),
            None => Ok(Value::Map(out)),
        };
    }
    Err(invalid(SHAPE))
}

/// A Records value for JavaScript.
pub(crate) fn value_out(value: &Value) -> JsValue {
    match value {
        Value::Unsigned(n) => unsigned(*n),
        Value::Negative(n) => {
            if *n < SAFE {
                JsValue::from_f64(-1.0 - *n as f64)
            } else {
                // -1 - n, as two's complement.
                BigInt::from(!i128::from(*n)).into()
            }
        }
        Value::Bool(b) => JsValue::from_bool(*b),
        Value::Float(f) => JsValue::from_f64(*f),
        Value::Bytes(data) => bytes(data),
        Value::Text(text) => JsValue::from_str(text),
        Value::Array(items) => array(items, value_out),
        Value::Map(map) => {
            let out = js_sys::Map::new();
            for (key, item) in map {
                out.set(&unsigned(*key), &value_out(item));
            }
            out.into()
        }
    }
}

/// A Loro value from JavaScript.
pub(crate) fn loro_in(value: &JsValue, depth: usize) -> Result<loro::LoroValue, JsValue> {
    use loro::LoroValue;
    const SHAPE: &str = "a document value is null, a boolean, a number, a string, a Uint8Array, an \
                         array of values or a plain object of values, nested at most 16 deep.";
    if depth > MAX_DEPTH {
        return Err(invalid(SHAPE));
    }
    let deeper = depth.saturating_add(1);
    if value.is_null() || value.is_undefined() {
        return Ok(LoroValue::Null);
    }
    if let Some(flag) = value.as_bool() {
        return Ok(LoroValue::Bool(flag));
    }
    if let Some(n) = value.as_f64() {
        let integral = n.is_finite() && n.fract() == 0.0 && n.abs() <= SAFE as f64;
        return Ok(if integral {
            LoroValue::I64(n as i64)
        } else {
            LoroValue::Double(n)
        });
    }
    if value.is_bigint() {
        return i64::try_from(value.clone())
            .map(LoroValue::I64)
            .map_err(|_| invalid("a document's bigint fits in 64 signed bits."));
    }
    if let Some(text) = value.as_string() {
        return Ok(LoroValue::from(text));
    }
    if let Some(data) = bytes_in(value) {
        return Ok(LoroValue::from(data));
    }
    if let Some(array) = value.dyn_ref::<Array>() {
        return array
            .iter()
            .map(|item| loro_in(&item, deeper))
            .collect::<Result<Vec<_>, _>>()
            .map(LoroValue::from);
    }
    if value.is_object() {
        let mut out = std::collections::HashMap::new();
        for entry in Object::entries(value.unchecked_ref::<Object>()).iter() {
            let key = Reflect::get_u32(&entry, 0)?
                .as_string()
                .ok_or_else(|| invalid(SHAPE))?;
            let item = loro_in(&Reflect::get_u32(&entry, 1)?, deeper)?;
            out.insert(key, item);
        }
        return Ok(LoroValue::from(out));
    }
    Err(invalid(SHAPE))
}

/// A Loro value for JavaScript.
pub(crate) fn loro_out(value: &loro::LoroValue) -> JsValue {
    use loro::LoroValue;
    match value {
        LoroValue::Null => JsValue::NULL,
        LoroValue::Bool(flag) => JsValue::from_bool(*flag),
        LoroValue::Double(n) => JsValue::from_f64(*n),
        LoroValue::I64(n) => {
            if n.unsigned_abs() <= SAFE {
                JsValue::from_f64(*n as f64)
            } else {
                BigInt::from(*n).into()
            }
        }
        LoroValue::Binary(data) => bytes(data),
        LoroValue::String(text) => JsValue::from_str(text),
        LoroValue::List(items) => array(items.iter(), loro_out),
        LoroValue::Map(map) => {
            let out = Obj::new();
            map.iter()
                .fold(out, |out, (key, item)| out.define(key, &loro_out(item)))
                .build()
        }
        LoroValue::Container(id) => JsValue::from_str(&id.to_string()),
    }
}
