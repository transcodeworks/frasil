//! `ext-deposit-tokens.json`'s `rotation`: the keys' shard read across
//! three periods, with the issuing and accepting key at each, the records
//! forgotten at each retirement, a wall clock ahead, and a restart with no
//! known wall clock (ext-deposit-tokens.md, 3.9 Spent tokens and key
//! rotation).

mod common;

use std::collections::BTreeSet;

use common::*;
use frasil_deposit_tokens::KeyShard;
use frasil_deposit_tokens::settings::TOKEN_PERIOD;
use frasil_testkit::hex;
use serde_json::{Value as Json, json};

fn describe(shard: &KeyShard, spent: &BTreeSet<(String, String)>) -> Json {
    let keys: Vec<Json> = shard
        .live_keys()
        .iter()
        .enumerate()
        .map(|(i, live)| {
            json!({
                "key_id": hex::encode(live.key.id()),
                "role": if i == 0 { "issuing" } else { "accepting only" },
                "began": {"timeline": live.began.timeline, "wall": live.began.wall,
                          "run": live.began.run},
            })
        })
        .collect();
    json!({
        "keys": keys,
        "spent": spent.iter().map(|(k, n)| json!([k, n])).collect::<Vec<_>>(),
    })
}

fn pairs(value: &Json) -> BTreeSet<(String, String)> {
    value
        .as_array()
        .unwrap()
        .iter()
        .map(|p| (text(&p[0]).to_owned(), text(&p[1]).to_owned()))
        .collect()
}

#[test]
fn rotation_across_three_periods() {
    let f = family("rotation");
    assert_eq!(number(&f["token_period"]), TOKEN_PERIOD);
    let steps = f["steps"].as_array().unwrap();
    let mut shard = KeyShard::new(TOKEN_PERIOD).unwrap();
    let first = &steps[0];
    let seed = array(&f["seeds"]["1"]);
    let rotation = shard.advance_with(reading(&first["now"]), &seed);
    assert!(rotation.retired.is_empty() && rotation.begun.is_some());
    let mut spent = pairs(&first["spent"]);
    assert_eq!(
        describe(&shard, &spent)["keys"],
        first["keys"],
        "{}",
        text(&first["step"])
    );
    for step in &steps[1..] {
        let name = text(&step["step"]);
        // The spends the step makes before it reads.
        spent = pairs(&step["before"]["spent"]);
        assert_eq!(describe(&shard, &spent), step["before"], "{name}");
        let rotation = shard.advance_with(reading(&step["now"]), &array(&step["next_seed"]));
        for retired in &rotation.retired {
            let id = hex::encode(retired);
            spent.retain(|(key, _)| key != &id);
        }
        let expected = json!({"keys": step["keys"], "spent": step["spent"]});
        assert_eq!(describe(&shard, &spent), expected, "{name}");
    }
}
