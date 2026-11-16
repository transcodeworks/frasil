//! What the ext-deposit-tokens.json tests share: the file, hex helpers,
//! verdicts, and a peer's state as the vectors' setups give it.

#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};

use frasil_base::errors::Class;
use frasil_base::time::Reading;
use frasil_deposit_tokens::budget::{Held, Mailboxes};
use frasil_deposit_tokens::peer::Window;
use frasil_deposit_tokens::rotation::LiveKey;
use frasil_deposit_tokens::settings::{DepositSettings, TOKEN_PERIOD};
use frasil_deposit_tokens::{DepositKey, IssuanceRecords, Issued, KeyShard, TokenClass};
use frasil_libraries::{LibraryId, LibraryState, PeerRecords, TicketId, TrustedIssuers};
use frasil_testkit::hex;
use frasil_transport::caps::Cap;
use serde_json::{Value as Json, json};

pub const FILE: &str = "ext-deposit-tokens.json";

pub fn family(name: &str) -> Json {
    frasil_testkit::vectors::family(FILE, name)
}

pub fn bytes(value: &Json) -> Vec<u8> {
    hex::decode(value.as_str().expect("hex")).expect("hex")
}

pub fn array<const N: usize>(value: &Json) -> [u8; N] {
    hex::decode_array(value.as_str().expect("hex")).expect("hex")
}

pub fn text(value: &Json) -> &str {
    value.as_str().expect("text")
}

pub fn number(value: &Json) -> u64 {
    value.as_u64().expect("a number")
}

pub fn map(bytes: &[u8]) -> frasil_base::cbor::Map {
    frasil_base::cbor::decode(bytes)
        .unwrap()
        .as_map()
        .unwrap()
        .clone()
}

pub fn reading(value: &Json) -> Reading {
    Reading {
        timeline: number(&value["timeline"]),
        wall: value["wall"].as_u64(),
        run: number(&value["run"]),
    }
}

/// Checks a refusal against a row's verdict, code and status.
pub fn refused(row: &Json, class: TokenClass) {
    let name = row.get("name").map_or("", text);
    assert_eq!(class.name(), text(&row["verdict"]), "{name}");
    assert_eq!(class.code(), row.get("code").map(text), "{name}");
    assert_eq!(
        class.status(),
        row.get("status").and_then(Json::as_u64).map(|s| s as u16),
        "{name}"
    );
}

/// The item ID the vectors write as a number.
pub fn item_id(value: &Json) -> [u8; 16] {
    u128::from(number(value)).to_be_bytes()
}

pub fn item_number(id: &[u8; 16]) -> u128 {
    u128::from_be_bytes(*id)
}

/// A library as a setup gives it.
#[derive(Debug, Clone)]
pub struct Library {
    pub state: LibraryState,
    pub settings: DepositSettings,
    pub window: Option<Window>,
    pub shares: BTreeMap<[u8; 32], u64>,
}

/// A peer's issuance state: its libraries, its spaces' libraries and the
/// ticket IDs it has used.
#[derive(Debug, Clone)]
pub struct Records {
    pub libraries: BTreeMap<String, Library>,
    pub spaces: BTreeMap<[u8; 32], String>,
    pub used: BTreeSet<TicketId>,
}

impl PeerRecords for Records {
    fn ticket_used(&self, id: &TicketId) -> bool {
        self.used.contains(id)
    }

    fn library_state(&self, library: &LibraryId) -> Option<LibraryState> {
        self.libraries.get(library.as_str()).map(|lib| lib.state)
    }

    fn deposit_tokens(&self) -> bool {
        true
    }
}

impl IssuanceRecords for Records {
    fn space_library(&self, space: &[u8; 32]) -> Option<LibraryId> {
        self.spaces
            .get(space)
            .map(|name| LibraryId::new(name).unwrap())
    }

    fn deposit_settings(&self, library: &LibraryId) -> DepositSettings {
        self.libraries
            .get(library.as_str())
            .map(|lib| lib.settings)
            .unwrap_or_default()
    }

    fn window(&self, library: &LibraryId) -> Option<Window> {
        self.libraries
            .get(library.as_str())
            .and_then(|lib| lib.window)
    }

    fn space_drawn(&self, library: &LibraryId, space: &[u8; 32]) -> u64 {
        self.libraries
            .get(library.as_str())
            .and_then(|lib| lib.shares.get(space).copied())
            .unwrap_or(0)
    }
}

impl Records {
    pub fn from_setup(setup: &Json) -> Self {
        let libraries = setup["libraries"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(name, lib)| {
                let state = LibraryState::from_name(text(&lib["state"])).unwrap();
                let window = lib["window_start"].as_u64().map(|start| Window {
                    start,
                    drawn: number(&lib["tokens_drawn"]),
                });
                let shares = lib["shares"]
                    .as_object()
                    .unwrap()
                    .iter()
                    .map(|(space, n)| (hex::decode_array(space).unwrap(), number(n)))
                    .collect();
                let settings = DepositSettings {
                    deposit_allowance: number(&lib["deposit_allowance"]),
                    space_share: number(&lib["space_share"]),
                };
                (
                    name.clone(),
                    Library {
                        state,
                        settings,
                        window,
                        shares,
                    },
                )
            })
            .collect();
        let spaces = setup["spaces"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(space, name)| (hex::decode_array(space).unwrap(), text(name).to_owned()))
            .collect();
        let used = setup["grants_used"]
            .as_array()
            .unwrap()
            .iter()
            .map(array::<16>)
            .collect();
        Self {
            libraries,
            spaces,
            used,
        }
    }

    /// Records what an issue returns, in one step.
    pub fn apply(&mut self, issued: &Issued) {
        let lib = self
            .libraries
            .entry(issued.library.as_str().to_owned())
            .or_insert_with(|| Library {
                state: LibraryState::Open,
                settings: DepositSettings::default(),
                window: None,
                shares: BTreeMap::new(),
            });
        if lib.window.map(|w| w.start) != Some(issued.window.start) {
            lib.shares.clear();
        }
        lib.window = Some(issued.window);
        if let Some((space, drawn)) = issued.space {
            lib.shares.insert(space, drawn);
        }
        if let Some((id, _)) = issued.grant {
            self.used.insert(id);
        }
    }

    /// The state as the vectors describe it.
    pub fn describe(&self) -> Json {
        let libraries: serde_json::Map<String, Json> = self
            .libraries
            .iter()
            .map(|(name, lib)| {
                let shares: serde_json::Map<String, Json> = lib
                    .shares
                    .iter()
                    .map(|(space, n)| (hex::encode(space), json!(n)))
                    .collect();
                (
                    name.clone(),
                    json!({
                        "state": lib.state.name(),
                        "deposit_allowance": lib.settings.deposit_allowance,
                        "space_share": lib.settings.space_share,
                        "window_start": lib.window.map(|w| w.start),
                        "tokens_drawn": lib.window.map_or(0, |w| w.drawn),
                        "shares": shares,
                    }),
                )
            })
            .collect();
        let spaces: serde_json::Map<String, Json> = self
            .spaces
            .iter()
            .map(|(space, name)| (hex::encode(space), json!(name)))
            .collect();
        json!({
            "libraries": libraries,
            "spaces": spaces,
            "grants_used": self.used.iter().map(hex::encode).collect::<Vec<_>>(),
        })
    }

    pub fn ledger(&self, name: &str) -> Json {
        let lib = &self.libraries[name];
        json!({
            "library": name,
            "tokens_drawn": lib.window.map_or(0, |w| w.drawn),
            "deposit_allowance": lib.settings.deposit_allowance,
        })
    }
}

/// The keys a setup lists, the issuing key first, under the default
/// `token_period`.
pub fn keys(setup_keys: &Json) -> KeyShard {
    let began = Reading {
        timeline: 0,
        wall: None,
        run: 1,
    };
    let live = setup_keys
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| {
            let key = DepositKey::from_seed(&array(&entry["seed"]));
            assert_eq!(hex::encode(key.id()), text(&entry["key_id"]));
            LiveKey { key, began }
        })
        .collect();
    let shard = KeyShard::from_keys(TOKEN_PERIOD, live).unwrap();
    for (entry, row) in shard.entries().iter().zip(setup_keys.as_array().unwrap()) {
        let role = match entry.role {
            frasil_deposit_tokens::Role::Issuing => "issuing",
            frasil_deposit_tokens::Role::Accepting => "accepting only",
        };
        assert_eq!(role, text(&row["role"]));
    }
    shard
}

pub fn issuers(setup: &Json) -> TrustedIssuers {
    TrustedIssuers::new(setup["issuers"].as_array().unwrap().iter().map(array)).unwrap()
}

/// Device mailboxes under two budgets, as the vectors describe them.
pub fn mailboxes(anonymous: &Json, tokens: &Json, described: &Json) -> Mailboxes {
    let cap = |c: &Json| Cap {
        items: number(&c["items"]),
        bytes: number(&c["bytes"]),
    };
    let mut highest = 0;
    let mut boxes = Vec::new();
    for row in described.as_array().unwrap() {
        let items: Vec<Held> = row["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|item| Held {
                id: item_id(&item[0]),
                bytes: number(&item[1]),
                paid: text(&item[2]) == "token",
            })
            .collect();
        highest = highest.max(items.iter().map(|i| item_number(&i.id)).max().unwrap_or(0));
        boxes.push((
            array::<32>(&row["address"]),
            row["claimed"].as_bool().unwrap(),
            items,
        ));
    }
    let mut out = Mailboxes::new(cap(anonymous), cap(tokens), highest + 1);
    for (address, claimed, items) in boxes {
        let mailbox = out.mailbox(address);
        mailbox.claimed = claimed;
        mailbox.items = items;
    }
    out
}

pub fn describe_mailboxes(mailboxes: &Mailboxes) -> Json {
    Json::Array(
        mailboxes
            .mailboxes()
            .iter()
            .map(|(address, mailbox)| {
                json!({
                    "address": hex::encode(address),
                    "claimed": mailbox.claimed,
                    "items": mailbox
                        .items
                        .iter()
                        .map(|i| json!([item_number(&i.id), i.bytes,
                                        if i.paid { "token" } else { "anonymous" }]))
                        .collect::<Vec<_>>(),
                })
            })
            .collect(),
    )
}
