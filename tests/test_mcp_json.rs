// montauk-mcp's hand-rolled JSON parser/serializer (montauk_mcp::json) -- the
// first thing in montauk that reads JSON, since include/util/json.h is
// write-only by design.

use montauk_mcp::json::{parse, Value};

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
