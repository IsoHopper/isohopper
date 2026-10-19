// SPDX-License-Identifier: GPL-3.0-or-later
use crate::{
    Config, ConfigError, Format, MAX_BYTES, MAX_DEPTH, MAX_NODES, MAX_SCALAR_BYTES, validate_value,
};
use saphyr_parser::{Event, Parser, ScalarStyle, Span, StrInput};
use serde_json::{Map, Number, Value};

pub fn parse(data: &[u8], format: &str) -> Result<Config, ConfigError> {
    if data.len() > MAX_BYTES {
        return Err(invalid(format!(
            "configuration exceeds {MAX_BYTES} byte limit"
        )));
    }
    let text = std::str::from_utf8(data)
        .map_err(|e| invalid(format!("configuration is not UTF-8: {e}")))?;
    let value = match Format::from_name(format)? {
        Format::Yaml => yaml(text)?,
        Format::Toml => {
            let table = text
                .parse::<toml::Table>()
                .map_err(|e| invalid(format!("TOML: {e}")))?;
            toml_value(toml::Value::Table(table), 1, &mut 0)?
        }
    };
    validate_value(&value)?;
    serde_json::from_value(value).map_err(|e| invalid(format!("configuration: {e}")))
}

fn invalid(message: impl Into<String>) -> ConfigError {
    ConfigError::Invalid(message.into())
}
fn at(span: Span, message: impl std::fmt::Display) -> ConfigError {
    invalid(format!(
        "YAML at line {}, column {}: {message}",
        span.start.line(),
        span.start.col() + 1
    ))
}
fn count_node(depth: usize, nodes: &mut usize) -> Result<(), ConfigError> {
    *nodes += 1;
    if depth > MAX_DEPTH {
        return Err(invalid(format!("depth exceeds limit {MAX_DEPTH}")));
    }
    if *nodes > MAX_NODES {
        return Err(invalid(format!("node count exceeds limit {MAX_NODES}")));
    }
    Ok(())
}
fn check_scalar(value: &str) -> Result<(), ConfigError> {
    if value.len() > MAX_SCALAR_BYTES {
        return Err(invalid(format!(
            "scalar exceeds {MAX_SCALAR_BYTES} byte limit"
        )));
    }
    Ok(())
}

fn yaml(text: &str) -> Result<Value, ConfigError> {
    let mut parser = Parser::new_from_str(text);
    let mut documents = 0;
    let mut output = None;
    let mut nodes = 0;
    while let Some(next) = parser.next() {
        let (event, span) = next.map_err(|e| invalid(format!("YAML: {e}")))?;
        match event {
            Event::StreamStart | Event::StreamEnd | Event::DocumentEnd => {}
            Event::DocumentStart(_) => {
                documents += 1;
                if documents > 1 {
                    return Err(at(span, "only one document is allowed"));
                }
                let (event, span) = next_event(&mut parser)?;
                output = Some(yaml_value(event, span, &mut parser, 1, &mut nodes)?);
            }
            _ => return Err(at(span, "unexpected event outside a document")),
        }
    }
    Ok(output.unwrap_or_else(|| Value::Object(Map::new())))
}

fn next_event<'a>(parser: &mut Parser<'a, StrInput<'a>>) -> Result<(Event<'a>, Span), ConfigError> {
    parser
        .next()
        .ok_or_else(|| invalid("unexpected end of YAML"))?
        .map_err(|e| invalid(format!("YAML: {e}")))
}

fn yaml_value<'a>(
    event: Event<'a>,
    span: Span,
    parser: &mut Parser<'a, StrInput<'a>>,
    depth: usize,
    nodes: &mut usize,
) -> Result<Value, ConfigError> {
    count_node(depth, nodes).map_err(|e| at(span, e))?;
    match event {
        Event::Alias(_) => Err(at(span, "aliases are not allowed")),
        Event::Scalar(value, style, anchor, tag) => {
            if anchor != 0 {
                return Err(at(span, "anchors are not allowed"));
            }
            if tag.is_some() {
                return Err(at(span, "explicit YAML tags are not allowed"));
            }
            check_scalar(&value).map_err(|e| at(span, e))?;
            if style == ScalarStyle::Plain {
                core_scalar(&value).map_err(|e| at(span, e))
            } else {
                Ok(Value::String(value.into_owned()))
            }
        }
        Event::MappingStart(anchor, tag) => {
            if anchor != 0 || tag.is_some() {
                return Err(at(span, "anchors and explicit YAML tags are not allowed"));
            }
            let mut map = Map::new();
            loop {
                let (event, key_span) = next_event(parser)?;
                if event == Event::MappingEnd {
                    break;
                }
                let Value::String(key) = yaml_value(event, key_span, parser, depth + 1, nodes)?
                else {
                    return Err(at(key_span, "mapping keys must be strings"));
                };
                if key == "<<" {
                    return Err(at(key_span, "merge keys are not allowed"));
                }
                if map.contains_key(&key) {
                    return Err(at(key_span, format!("duplicate key {key:?}")));
                }
                let (event, value_span) = next_event(parser)?;
                map.insert(
                    key,
                    yaml_value(event, value_span, parser, depth + 1, nodes)?,
                );
            }
            Ok(Value::Object(map))
        }
        Event::SequenceStart(anchor, tag) => {
            if anchor != 0 || tag.is_some() {
                return Err(at(span, "anchors and explicit YAML tags are not allowed"));
            }
            let mut values = Vec::new();
            loop {
                let (event, span) = next_event(parser)?;
                if event == Event::SequenceEnd {
                    break;
                }
                values.push(yaml_value(event, span, parser, depth + 1, nodes)?);
            }
            Ok(Value::Array(values))
        }
        _ => Err(at(span, "expected a scalar, sequence, or mapping")),
    }
}

fn core_scalar(value: &str) -> Result<Value, ConfigError> {
    match value {
        "" | "~" | "null" | "Null" | "NULL" => return Ok(Value::Null),
        "true" | "True" | "TRUE" => return Ok(Value::Bool(true)),
        "false" | "False" | "FALSE" => return Ok(Value::Bool(false)),
        _ => {}
    }
    let unsigned = value.strip_prefix(['+', '-']).unwrap_or(value);
    if !unsigned.is_empty() && unsigned.bytes().all(|b| b.is_ascii_digit()) {
        return value
            .parse::<i64>()
            .map(|n| Value::Number(n.into()))
            .map_err(|_| invalid("integer outside supported 64-bit range"));
    }
    for (prefix, radix) in [("0x", 16), ("0o", 8)] {
        if let Some(digits) = value.strip_prefix(prefix)
            && !digits.is_empty()
            && digits.chars().all(|c| c.is_digit(radix))
        {
            return i64::from_str_radix(digits, radix)
                .map(|n| Value::Number(n.into()))
                .map_err(|_| invalid("integer outside supported 64-bit range"));
        }
    }
    if matches!(
        value.to_ascii_lowercase().as_str(),
        ".nan" | ".inf" | "+.inf" | "-.inf"
    ) {
        return Err(invalid("non-finite numbers are not supported"));
    }
    if value.contains(['.', 'e', 'E'])
        && value.bytes().any(|b| b.is_ascii_digit())
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || b"+-.eE".contains(&b))
        && let Ok(number) = value.parse::<f64>()
    {
        return finite_number(number);
    }
    Ok(Value::String(value.into()))
}

fn finite_number(number: f64) -> Result<Value, ConfigError> {
    if !number.is_finite() {
        return Err(invalid("non-finite numbers are not supported"));
    }
    if number.fract() == 0.0 && number >= i64::MIN as f64 && number < i64::MAX as f64 {
        return Ok(Value::Number((number as i64).into()));
    }
    Number::from_f64(number)
        .map(Value::Number)
        .ok_or_else(|| invalid("invalid number"))
}

fn toml_value(value: toml::Value, depth: usize, nodes: &mut usize) -> Result<Value, ConfigError> {
    count_node(depth, nodes)?;
    match value {
        toml::Value::String(value) => {
            check_scalar(&value)?;
            Ok(Value::String(value))
        }
        toml::Value::Integer(value) => Ok(Value::Number(value.into())),
        toml::Value::Float(value) => finite_number(value),
        toml::Value::Boolean(value) => Ok(Value::Bool(value)),
        toml::Value::Datetime(_) => Err(invalid(
            "unsupported TOML scalar; quote dates and times to use strings",
        )),
        toml::Value::Array(values) => values
            .into_iter()
            .map(|v| toml_value(v, depth + 1, nodes))
            .collect::<Result<Vec<_>, _>>()
            .map(Value::Array),
        toml::Value::Table(table) => {
            let mut map = Map::new();
            for (key, value) in table {
                count_node(depth + 1, nodes)?;
                check_scalar(&key)?;
                map.insert(key, toml_value(value, depth + 1, nodes)?);
            }
            Ok(Value::Object(map))
        }
    }
}
