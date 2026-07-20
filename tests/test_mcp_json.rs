// vector's hand-rolled JSON parser/serializer (vector::json) -- the
// first thing in montauk that reads JSON, since include/util/json.h is
// write-only by design.

use vector::json::{parse, Value};

#[test]
fn parses_scalars() {
    assert_eq!(parse("null").unwrap(), Value::Null);
    assert_eq!(parse("true").unwrap(), Value::Bool(true));
    assert_eq!(parse("false").unwrap(), Value::Bool(false));
    assert_eq!(parse("42").unwrap(), Value::Number(42.0));
    assert_eq!(parse("-3.5e2").unwrap(), Value::Number(-350.0));
    assert_eq!(parse("\"hi\"").unwrap(), Value::String("hi".to_string()));
}

#[test]
fn parses_escapes() {
    let v = parse(r#""a\n\t\"bA""#).unwrap();
    assert_eq!(v, Value::String("a\n\t\"bA".to_string()));
}

#[test]
fn parses_unicode_escape() {
    let v = parse(r#""café""#).unwrap();
    assert_eq!(v, Value::String("caf\u{e9}".to_string()));
}

// The escape text is assembled from halves (concat!) so no tool in the
// edit chain ever sees a full 😀 pair to decode prematurely --
// the parser under test receives the exact 12-byte escape sequence.
const EMOJI_PAIR: &str = concat!(r"\ud83d", r"\ude00"); // U+1F600
const CJK_B_PAIR: &str = concat!(r"\ud840", r"\udc00"); // U+20000

#[test]
fn decodes_surrogate_pairs_to_non_bmp_code_points() {
    // U+1F600 as its UTF-16 escape pair -- one emoji out, not two U+FFFD.
    let v = parse(&format!("\"{EMOJI_PAIR}\"")).unwrap();
    assert_eq!(v, Value::String("\u{1F600}".to_string()));
    // Mid-string, with neighbors on both sides.
    let v = parse(&format!("\"a{EMOJI_PAIR}b\"")).unwrap();
    assert_eq!(v, Value::String("a\u{1F600}b".to_string()));
    // CJK Extension B (U+20000), the non-emoji non-BMP case.
    let v = parse(&format!("\"{CJK_B_PAIR}\"")).unwrap();
    assert_eq!(v, Value::String("\u{20000}".to_string()));
    // Raw (unescaped) UTF-8 non-BMP passthrough still works too.
    let v = parse("\"\u{1F600}\"").unwrap();
    assert_eq!(v, Value::String("\u{1F600}".to_string()));
}

#[test]
fn surrogate_pair_round_trips_through_serialize_and_parse() {
    let original = Value::String("emoji \u{1F600} and CJK-B \u{20000}".to_string());
    let reparsed = parse(&original.to_string()).unwrap();
    assert_eq!(original, reparsed);
}

#[test]
fn lone_high_surrogate_becomes_replacement_character() {
    assert_eq!(parse(r#""\ud83d""#).unwrap(), Value::String("\u{FFFD}".to_string()));
    // Followed by a non-surrogate escape: U+FFFD then the escape's own char.
    assert_eq!(parse(r#""\ud83dA""#).unwrap(), Value::String("\u{FFFD}A".to_string()));
    // Followed by a plain character rather than another escape.
    assert_eq!(parse(r#""\ud83dx""#).unwrap(), Value::String("\u{FFFD}x".to_string()));
}

#[test]
fn swapped_surrogate_pair_becomes_two_replacement_characters() {
    // Low then high: neither half can pair, both keep the U+FFFD convention.
    let v = parse(r#""\ude00\ud83d""#).unwrap();
    assert_eq!(v, Value::String("\u{FFFD}\u{FFFD}".to_string()));
}

#[test]
fn high_surrogate_then_valid_pair_recovers_the_pair() {
    // A lone \ud83d, then a real pair -- the second high surrogate must
    // not be swallowed by the first's failed pairing.
    let v = parse(&format!("\"{}{EMOJI_PAIR}\"", r"\ud83d")).unwrap();
    assert_eq!(v, Value::String("\u{FFFD}\u{1F600}".to_string()));
}

#[test]
fn parses_nested_object_and_array() {
    let v = parse(r#"{"a":[1,2,3],"b":{"c":null}}"#).unwrap();
    assert_eq!(v.get("a").unwrap().as_array().unwrap().len(), 3);
    assert_eq!(v.get("b").unwrap().get("c").unwrap(), &Value::Null);
}

#[test]
fn rejects_trailing_garbage() {
    assert!(parse("42 garbage").is_err());
}

#[test]
fn rejects_truncated_input() {
    assert!(parse("{\"a\":").is_err());
    assert!(parse("[1,2").is_err());
    assert!(parse("\"unterminated").is_err());
}

#[test]
fn round_trips_through_serialize_and_parse() {
    let original = Value::obj(vec![
        ("name", Value::String("wake2run_p99_us".to_string())),
        ("value", Value::Number(8.3)),
        ("ok", Value::Bool(true)),
        ("tags", Value::Array(vec![Value::Number(1.0), Value::Number(2.0)])),
    ]);
    let text = original.to_string();
    let reparsed = parse(&text).unwrap();
    assert_eq!(original, reparsed);
}

#[test]
fn serializes_control_characters_escaped() {
    let v = Value::String("line1\nline2\ttab".to_string());
    let text = v.to_string();
    assert_eq!(parse(&text).unwrap(), v);
    assert!(!text.contains('\n'));
}

#[test]
fn integer_valued_numbers_serialize_without_a_decimal_point() {
    // Matches montauk's existing JSON writer convention (json.h): a whole
    // number like an event count renders as `42`, not `42.0`.
    assert_eq!(Value::Number(42.0).to_string(), "42");
    assert_eq!(Value::Number(-7.0).to_string(), "-7");
    assert_eq!(Value::Number(2.5).to_string(), "2.5");
}
