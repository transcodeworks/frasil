//! A connection to an always-on peer, as a JavaScript class.

use crate::convert::{Obj, array, number};
use wasm_bindgen::prelude::*;

/// A connection to an always-on peer.
#[wasm_bindgen]
pub struct Peer {
    inner: frasil::Peer,
}

impl From<frasil::Peer> for Peer {
    fn from(inner: frasil::Peer) -> Self {
        Self { inner }
    }
}

#[wasm_bindgen]
impl Peer {
    /// The URL the device connected to.
    #[wasm_bindgen(getter)]
    pub fn url(&self) -> String {
        self.inner.url().to_owned()
    }

    /// What the connection has done: `{ connected, reconnecting,
    /// reconnects, closed, spaces, refused, refusedChanges, recoveryEntries,
    /// withheld, rolledBack }`. `reconnecting` is whether it is connecting again because the peer
    /// asked it to, which is no error, and `reconnects` how many times it
    /// has; `closed` is why it ended, or
    /// `null`; `spaces` the IDs of the spaces the peer keeps; `refused` lists
    /// `{ space, code }`; `recoveryEntries` counts the fetch keys the peer
    /// registered on this connection; `withheld` and `rolledBack` the IDs
    /// of the spaces in which the peer served less than the device knows
    /// of, or no longer held events it acknowledged, since the device
    /// opened.
    pub fn status(&self) -> JsValue {
        let status = self.inner.status();
        Obj::new()
            .set("connected", status.connected)
            .set("reconnecting", status.reconnecting)
            .set(
                "reconnects",
                number(usize::try_from(status.reconnects).unwrap_or(usize::MAX)),
            )
            .set("closed", status.closed.map_or(JsValue::NULL, JsValue::from))
            .set(
                "spaces",
                array(status.spaces, |space| JsValue::from(space.to_string())),
            )
            .set(
                "refused",
                array(status.refused, |(space, code)| {
                    Obj::new()
                        .set("space", space.to_string())
                        .set("code", code)
                        .build()
                }),
            )
            .set("refusedChanges", number(status.refused_changes))
            .set("recoveryEntries", number(status.recovery_entries))
            .set(
                "withheld",
                array(status.withheld, |space| JsValue::from(space.to_string())),
            )
            .set(
                "rolledBack",
                array(status.rolled_back, |space| JsValue::from(space.to_string())),
            )
            .build()
    }

    /// Closes the connection.
    pub fn close(&self) {
        self.inner.close();
    }
}
