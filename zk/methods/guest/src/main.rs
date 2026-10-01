// Relation R of Eq. (5), executed inside the RISC Zero zkVM.
//
// Private input (witness): theta, r, x, r_i and the action a, together with the
// public fields v, predicate_id and kappa.  The guest recomputes
//   C_v = Com(Enc(v, theta); r),  X_i = Com(Enc(kappa, x); r_i),  D_i = H(Enc(action, a))
// with exactly the encodings and domain labels of abd/crypto.py and abd/predicate.py,
// evaluates q_i = Q_{v,theta}(x, a), and commits the canonical encoding of the public
// statement (C_v, X_i, kappa, D_i, v, predicate_id, q_i) as the journal.  Nothing else
// leaves the guest.

use risc0_zkvm::guest::env;
use serde_json::Value;
use sha2::{Digest, Sha384};

const DOMAIN_COMMITMENT: &[u8] = b"ABD/v2/commitment";
const DOMAIN_ACTION: &[u8] = b"ABD/v2/action";
const SAFE_INT: i64 = (1i64 << 53) - 1;

// Canonical encoding identical to abd/canonical.py: printable-ASCII strings with JSON
// escaping of '"' and '\', integers within +-(2^53-1), sorted object keys, no whitespace.
fn canon(v: &Value, out: &mut Vec<u8>) {
    match v {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(b) => out.extend_from_slice(if *b { b"true" } else { b"false" }),
        Value::Number(n) => {
            let i = n.as_i64().expect("only integers are allowed");
            assert!((-SAFE_INT..=SAFE_INT).contains(&i), "integer outside the interoperable range");
            out.extend_from_slice(i.to_string().as_bytes());
        }
        Value::String(s) => canon_str(s, out),
        Value::Array(items) => {
            out.push(b'[');
            for (k, item) in items.iter().enumerate() {
                if k > 0 {
                    out.push(b',');
                }
                canon(item, out);
            }
            out.push(b']');
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            out.push(b'{');
            for (k, key) in keys.iter().enumerate() {
                if k > 0 {
                    out.push(b',');
                }
                canon_str(key, out);
                out.push(b':');
                canon(&map[key.as_str()], out);
            }
            out.push(b'}');
        }
    }
}

fn canon_str(s: &str, out: &mut Vec<u8>) {
    out.push(b'"');
    for c in s.bytes() {
        assert!((0x20..=0x7e).contains(&c), "string contains characters outside printable ASCII");
        match c {
            b'"' => out.extend_from_slice(b"\\\""),
            b'\\' => out.extend_from_slice(b"\\\\"),
            _ => out.push(c),
        }
    }
    out.push(b'"');
}

fn encode(v: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    canon(v, &mut out);
    out
}

// domain_digest_hex of abd/crypto.py: SHA-384(domain || 0x00 || data), lower-case hex.
fn domain_digest_hex(domain: &[u8], data: &[u8]) -> String {
    let mut h = Sha384::new();
    h.update(domain);
    h.update([0u8]);
    h.update(data);
    hex::encode(h.finalize())
}

// commit() of abd/predicate.py: Com(m; r) over len(r) as two big-endian bytes, r, m.
fn commit(message: &[u8], r: &[u8]) -> String {
    assert_eq!(r.len(), 32, "commitment randomness must be 32 bytes");
    let mut data = Vec::with_capacity(2 + r.len() + message.len());
    data.extend_from_slice(&(r.len() as u16).to_be_bytes());
    data.extend_from_slice(r);
    data.extend_from_slice(message);
    domain_digest_hex(DOMAIN_COMMITMENT, &data)
}

fn object(pairs: &[(&str, &Value)]) -> Value {
    let mut map = serde_json::Map::new();
    for (k, v) in pairs {
        map.insert((*k).to_string(), (*v).clone());
    }
    Value::Object(map)
}

// Predicate catalogue (abd/predicate.py PREDICATES).
fn predicate(id: &str, theta: &Value, x: &Value, a: &Value) -> bool {
    match id {
        "rotation_threshold_v1" => {
            let age = x["key_age_days"].as_i64().expect("x.key_age_days");
            let min = theta["min_key_age_days"].as_i64().expect("theta.min_key_age_days");
            let target = a["target_profile_id"].as_str().expect("action.target_profile_id");
            let permitted = theta["permitted_profiles"].as_array().expect("theta.permitted_profiles");
            age >= min && permitted.iter().any(|p| p.as_str() == Some(target))
        }
        other => panic!("unknown predicate {other}"),
    }
}

fn main() {
    let input: String = env::read();
    let w: Value = serde_json::from_str(&input).expect("witness is not JSON");
    let predicate_id = w["predicate_id"].as_str().expect("predicate_id");
    let (v, theta, x, kappa, action) = (&w["v"], &w["theta"], &w["x"], &w["kappa"], &w["action"]);
    let r = hex::decode(w["r"].as_str().expect("r")).expect("r is not hex");
    let r_i = hex::decode(w["r_i"].as_str().expect("r_i")).expect("r_i is not hex");

    let c_v = commit(&encode(&object(&[("v", v), ("theta", theta)])), &r);
    let x_i = commit(&encode(&object(&[("kappa", kappa), ("x", x)])), &r_i);
    let d_i = domain_digest_hex(DOMAIN_ACTION, &encode(action));
    let q_i = predicate(predicate_id, theta, x, action);

    let statement = object(&[
        ("C_v", &Value::String(c_v)),
        ("X_i", &Value::String(x_i)),
        ("kappa", kappa),
        ("D_i", &Value::String(d_i)),
        ("v", v),
        ("predicate_id", &Value::String(predicate_id.to_string())),
        ("q_i", &Value::Bool(q_i)),
    ]);
    env::commit_slice(&encode(&statement));
}
