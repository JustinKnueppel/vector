use crate::{config::log_schema, event::Event, sources::util::http::ErrorMessage};
use bytes::{Bytes, BytesMut};
use chrono::Utc;
use codec::BytesDelimitedCodec;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use shared::log_event;
use tokio_util::codec::Decoder;
use warp::http::StatusCode;

#[derive(Deserialize, Serialize, Debug, Eq, PartialEq, Clone, Derivative, Copy)]
#[serde(rename_all = "snake_case")]
#[derivative(Default)]
pub enum Encoding {
    #[derivative(Default)]
    Text,
    Ndjson,
    Json,
}

#[cfg(any(feature = "sources-http", feature = "sources-datadog"))]
fn body_to_lines(buf: Bytes) -> impl Iterator<Item = Result<Bytes, ErrorMessage>> {
    let mut body = BytesMut::new();
    body.extend_from_slice(&buf);

    let mut decoder = BytesDelimitedCodec::new(b'\n');
    std::iter::from_fn(move || {
        match decoder.decode_eof(&mut body) {
            Err(error) => Some(Err(ErrorMessage::new(
                StatusCode::BAD_REQUEST,
                format!("Bad request: {}", error),
            ))),
            Ok(Some(b)) => Some(Ok(b)),
            Ok(None) => None, // actually done
        }
    })
    .filter(|s| match s {
        // filter empty lines
        Ok(b) => !b.is_empty(),
        _ => true,
    })
}

#[cfg(any(feature = "sources-http", feature = "sources-datadog"))]
pub fn decode_body(body: Bytes, enc: Encoding) -> Result<Vec<Event>, ErrorMessage> {
    match enc {
        Encoding::Text => body_to_lines(body)
            .map(|r| {
                Ok(log_event! {
                    log_schema().message_key().clone() => r?,
                    log_schema().timestamp_key().clone() => chrono::Utc::now(),
                })
            })
            .collect::<Result<_, _>>(),
        Encoding::Ndjson => body_to_lines(body)
            .map(|j| {
                let parsed_json = serde_json::from_slice(&j?)
                    .map_err(|error| json_error(format!("Error parsing Ndjson: {:?}", error)))?;
                json_parse_object(parsed_json)
            })
            .collect::<Result<_, _>>(),
        Encoding::Json => {
            let parsed_json = serde_json::from_slice(&body)
                .map_err(|error| json_error(format!("Error parsing Json: {:?}", error)))?;
            json_parse_array_of_object(parsed_json)
        }
    }
}

#[cfg(any(feature = "sources-http", feature = "sources-datadog"))]
fn json_parse_object(value: JsonValue) -> Result<Event, ErrorMessage> {
    let mut event = Event::new_empty_log();
    let log = event.as_mut_log();
    log.insert(log_schema().timestamp_key().clone(), Utc::now()); // Add timestamp
    match value {
        JsonValue::Object(map) => {
            for (k, v) in map {
                log.insert_flat(k, v);
            }
            Ok(event)
        }
        _ => Err(json_error(format!(
            "Expected Object, got {}",
            json_value_to_type_string(&value)
        ))),
    }
}

#[cfg(any(feature = "sources-http", feature = "sources-datadog"))]
fn json_parse_array_of_object(value: JsonValue) -> Result<Vec<Event>, ErrorMessage> {
    match value {
        JsonValue::Array(v) => v
            .into_iter()
            .map(json_parse_object)
            .collect::<Result<_, _>>(),
        JsonValue::Object(map) => {
            //treat like an array of one object
            Ok(vec![json_parse_object(JsonValue::Object(map))?])
        }
        _ => Err(json_error(format!(
            "Expected Array or Object, got {}.",
            json_value_to_type_string(&value)
        ))),
    }
}

#[cfg(any(feature = "sources-http", feature = "sources-datadog"))]
fn json_error(s: String) -> ErrorMessage {
    ErrorMessage::new(StatusCode::BAD_REQUEST, format!("Bad JSON: {}", s))
}

#[cfg(any(feature = "sources-http", feature = "sources-datadog"))]
fn json_value_to_type_string(value: &JsonValue) -> &'static str {
    match value {
        JsonValue::Object(_) => "Object",
        JsonValue::Array(_) => "Array",
        JsonValue::String(_) => "String",
        JsonValue::Number(_) => "Number",
        JsonValue::Bool(_) => "Bool",
        JsonValue::Null => "Null",
    }
}
