// SPDX-FileCopyrightText: 2021 Andrew 'glyph' Reid
//
// SPDX-License-Identifier: LGPL-3.0-only

//! # Binary Field Encodings (BFE) for Secure Scuttlebutt (SSB).
//!
//! Based on the JavaScript reference implementation: [ssb-bfe](https://github.com/ssb-ngi-pointer/ssb-bfe) (written according to the [specification](https://github.com/ssb-ngi-pointer/ssb-binary-field-encodings-spec)).
//!
//! While `encode()` and `decode()` are the two primary functions exposed by this crate, the
//! various helper functions and values are also exported for public use.
//!
//! ## Encode
//!
//! The encoder expects JSON input in the form of a [`serde_json::Value
//! enum`](https://docs.serde.rs/serde_json/value/enum.Value.html). The encoded value is returned
//! as an `BfeValue` (a custom `enum` provided by this library).
//!
//! ## Decode
//!
//! The decoder expects input in the form of an `BfeValue` (a custom `enum` provided by this
//! library). The decoded value is returned as JSON in the form of a [`serde_json::Value enum`](https://docs.serde.rs/serde_json/value/enum.Value.html).
//!
//!`Deserialize` and `Serialize` traits have been derived for `BfeValue`,
//!meaning that encoded JSON objects can be parsed into the `BfeValue`
//!type if required (for example, if the value is received as a byte slice of
//!serialized JSON data). See the `serde` documentation on
//![Parsing JSON as strongly typed data structures](https://docs.serde.rs/serde_json/index.html#parsing-json-as-strongly-typed-data-structures) for an example and further explanation.
//!
//! ## Example
//!
//!```
//! use serde_json::json;
//!
//! let value = json!({
//!     "author": "@6CAxOI3f+LUOVrbAl0IemqiS7ATpQvr9Mdw9LC4+Uv0=.ed25519",
//!     "previous": "%R8heq/tQoxEIPkWf0Kxn1nCm/CsxG2CDpUYnAvdbXY8=.sha256",
//!     "bb_msg": "ssb:message/bendybutt-v1/HZVnEzm0NgoSVfG0Hx4gMFbMMHhFvhJsG2zK_pijYII="
//! });
//!
//! let encoded = ssb_bfe_rs::encode(&value);
//! let encoded_value = encoded.unwrap();
//! println!("{:X?}", encoded_value);
//!
//! // Object({"author": Buffer([0, 0, E8, 20, 31, 38, 8D, DF, F8, B5, E, 56, B6, C0, 97, 42, 1E, 9A, A8, 92, EC, 4, E9, 42, FA, FD, 31, DC, 3D, 2C, 2E, 3E, 52, FD]), "previous": Buffer([1, 0, 47, C8, 5E, AB, FB, 50, A3, 11, 8, 3E, 45, 9F, D0, AC, 67, D6, 70, A6, FC, 2B, 31, 1B, 60, 83, A5, 46, 27, 2, F7, 5B, 5D, 8F]), "bb_msg": Buffer([1, 4, 1D, 95, 67, 13, 39, B4, 36, A, 12, 55, F1, B4, 1F, 1E, 20, 30, 56, CC, 30, 78, 45, BE, 12, 6C, 1B, 6C, CA, FE, 98, A3, 60, 82])})
//!
//! let decoded = ssb_bfe_rs::decode(&encoded_value);
//! let decoded_value = decoded.unwrap();
//! println!("{:?}", decoded_value);
//!
//! // Object({"author": String("@6CAxOI3f+LUOVrbAl0IemqiS7ATpQvr9Mdw9LC4+Uv0=.ed25519"), "previous": String("%R8heq/tQoxEIPkWf0Kxn1nCm/CsxG2CDpUYnAvdbXY8=.sha256"), "bb_msg": String("ssb:message/bendybutt-v1/HZVnEzm0NgoSVfG0Hx4gMFbMMHhFvhJsG2zK_pijYII=")})
//! ```

pub mod data;

use std::str;

use anyhow::{anyhow, Context, Result};
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use ssb_uri_rs::Parts;

use crate::data::*;

/// Represents any valid BFE return value, including values for types which are encoded and those
/// which are not (ie. integers and floats).
#[derive(Debug, PartialEq, Deserialize, Serialize)]
pub enum BfeValue {
    /// Represents an array of encoded BFE values.
    Array(Vec<BfeValue>),
    /// Represents an encoded boolean, string, feed key, message key or signature key.
    Buffer(Vec<u8>),
    /// Represents an unencoded, floating point.
    Float(f64),
    /// Represents an object of encoded BFE values.
    #[serde(with = "indexmap::serde_seq")]
    Object(IndexMap<String, BfeValue>),
    /// Represents an unencoded, signed integer.
    SignedInteger(i64),
    /// Represents an unencoded, unsigned integer.
    UnsignedInteger(u64),
}

/// Take a blob ID as a string and return the encoded bytes representing the blob type-format.
pub fn get_blob_type(blob_id: &str) -> Result<Vec<u8>> {
    let blob_tf;
    if blob_id.ends_with(".sha256") {
        blob_tf = BLOB_FORMATS["classic"].0
    } else {
        return Err(anyhow!("Unknown blob ID: {}", blob_id));
    };

    Ok(blob_tf.to_vec())
}

/// Take a box as a string and return the encoded bytes representing the box type-format.
// Note: box refers to an SSB `private box` and not a Rust `Box` (pointer type)
pub fn get_box_type(boxed_str: &str) -> Result<Vec<u8>> {
    let box_tf;
    if boxed_str.ends_with(".box") {
        box_tf = ENCRYPTED_FORMATS["box1"].0
    } else if boxed_str.ends_with(".box2") {
        box_tf = ENCRYPTED_FORMATS["box2"].0
    } else {
        return Err(anyhow!("Unknown boxed string: {}", boxed_str));
    };

    Ok(box_tf.to_vec())
}

/// Take a feed ID (key) as a string and return the encoded bytes representing the feed type-format.
pub fn get_feed_type(feed_id: &str) -> Result<Vec<u8>> {
    let feed_tf;
    if feed_id.ends_with(".ed25519") {
        feed_tf = FEED_FORMATS["classic"].0
    } else {
        return Err(anyhow!("Unknown feed format: {}", feed_id));
    };

    Ok(feed_tf.to_vec())
}

/// Take a message ID as a string and return the encoded bytes representing the message type-format.
pub fn get_msg_type(msg_id: &str) -> Result<Vec<u8>> {
    let msg_tf;

    if msg_id.ends_with(".sha256") {
        msg_tf = MSG_FORMATS["classic"].0
    } else if msg_id.ends_with(".cloaked") {
        msg_tf = MSG_FORMATS["cloaked"].0
    } else {
        return Err(anyhow!("Unknown message ID: {}", msg_id));
    };

    Ok(msg_tf.to_vec())
}

/// Take a blob ID as a string and return the encoded bytes as a vector.
pub fn encode_blob(blob_id: &str) -> Result<Vec<u8>> {
    let mut encoded_blob = get_blob_type(blob_id)?;
    let dot_index = blob_id
        .rfind('.')
        .with_context(|| format!("Invalid blob ID; no dot index was found: {}", blob_id))?;
    let base64_str = &blob_id[1..dot_index];
    // decode blob substring from base64 (to bytes) and append to encoded_blob bytes
    base64::decode_config_buf(base64_str, base64::STANDARD, &mut encoded_blob)?;

    Ok(encoded_blob)
}

/// Take a boolean value as a string and return the encoded bytes as a vector.

pub fn encode_bool(boolean: &bool) -> Result<Vec<u8>> {
    let boolean_tf = GENERIC_FORMATS["boolean"].0;
    let bool_vec = match boolean {
        true => [boolean_tf, BOOL_TRUE].concat(),
        false => [boolean_tf, BOOL_FALSE].concat(),
    };

    Ok(bool_vec.to_vec())
}

/// Take a box key as a string and return the encoded bytes as a vector.
// Note: box refers to an SSB `private box` and not a Rust `Box` (pointer type)
pub fn encode_box(box_str: &str) -> Result<Vec<u8>> {
    let mut encoded_box = get_box_type(box_str)?;
    let dot_index = box_str
        .rfind('.')
        .context("Invalid box string: no dot index was found")?;
    let base64_str = &box_str[0..dot_index];
    // decode box substring from base64 (to bytes) and append to encoded_box bytes
    base64::decode_config_buf(base64_str, base64::STANDARD, &mut encoded_box)?;

    Ok(encoded_box)
}

/// Take a feed ID (key) as a string and return the encoded bytes as a vector.
pub fn encode_feed(feed: &str) -> Result<Vec<u8>> {
    let mut encoded_feed = get_feed_type(feed)?;
    let dot_index = feed
        .rfind('.')
        .with_context(|| format!("Invalid feed string; no dot index was found: {}", feed))?;
    let base64_str = &feed[1..dot_index];
    // decode feed substring from base64 (to bytes) and append to encoded_feed bytes
    base64::decode_config_buf(base64_str, base64::STANDARD, &mut encoded_feed)?;

    Ok(encoded_feed)
}

/// Take a message ID as a string and return the encoded bytes as a vector.
pub fn encode_msg(msg: &str) -> Result<Vec<u8>> {
    let mut encoded_msg = get_msg_type(msg)?;
    let dot_index = msg
        .rfind('.')
        .with_context(|| format!("Invalid message string; no dot index was found: {}", msg))?;
    let base64_str = &msg[1..dot_index];
    // decode msg substring from base64 str to bytes and append to encoded_msg bytes
    base64::decode_config_buf(base64_str, base64::STANDARD, &mut encoded_msg)?;

    Ok(encoded_msg)
}

/// Take a signature as a string and return the encoded bytes as a vector.
pub fn encode_sig(sig: &str) -> Result<Vec<u8>> {
    let mut encoded_sig = SIGNATURE_FORMATS["msg-ed25519"].0.to_vec();
    let sig_substring = sig.strip_suffix(".sig.ed25519").with_context(|| {
        format!(
            "Signature does not have a valid `.sig.ed25519` suffix: {}",
            sig,
        )
    })?;
    // decode sig substring from base64 str to bytes and append to encoded_sig bytes
    base64::decode_config_buf(sig_substring, base64::STANDARD, &mut encoded_sig)?;

    Ok(encoded_sig)
}

/// Take a string value and return the encoded bytes as a vector.
pub fn encode_string(string: &str) -> Result<Vec<u8>> {
    let string_tf = GENERIC_FORMATS["string-UTF8"].0;
    let encoded_string = [string_tf, string.as_bytes()].concat();

    Ok(encoded_string)
}

/// Take an SSB URI as a string and return the encoded bytes as a vector.
pub fn encode_uri(uri: &str) -> Result<Vec<u8>> {
    // no bfe encoding for multiserver address and experimental uris; treat as string
    if ssb_uri_rs::is_multiserver_uri(uri)? || ssb_uri_rs::is_experimental_uri(uri)? {
        Ok(encode_string(uri)?)
    } else {
        let Parts(uri_type, uri_format, uri_data) = ssb_uri_rs::decompose_uri(uri)?;
        match TYPES.contains_key(&uri_type) {
            // no match? encode the uri as a string
            false => Ok(encode_string(uri)?),
            true => {
                let (_, formats) = &TYPES[&uri_type];
                match formats.get(&uri_format) {
                    Some(format_data) => {
                        let type_format_code = format_data.0;
                        let data_len = format_data.1;
                        let b64_data = base64::decode_config(uri_data, base64::STANDARD)?;
                        if let Some(len) = data_len {
                            if len != b64_data.len() {
                                return Err(anyhow!(
                                    "expected data to be length {}, but found {}",
                                    len,
                                    b64_data.len()
                                ));
                            } else {
                                // concat the tf with the data and return it
                                let encoded_uri = [type_format_code, &b64_data[..]].concat();

                                Ok(encoded_uri)
                            }
                        } else {
                            Err(anyhow!(
                                "no data length exists for type `{}` with format `{}`",
                                uri_type,
                                uri_format
                            ))
                        }
                    }
                    // return error if format not recognised
                    None => Err(anyhow!(
                        "no encoder for type `{}` and format `{}` for SSB URI `{}`",
                        uri_type,
                        uri_format,
                        uri
                    )),
                }
            }
        }
    }
}

/// Take a JSON value, match on the value type(s) and call the appropriate encoder(s).
///
/// Returns the encoded value in the form of a `Result<BfeValue>`.
pub fn encode(value: &Value) -> Result<BfeValue> {
    match value {
        Value::Array(v) => {
            let mut encoded_arr = Vec::new();
            for item in v {
                let encoded_item = encode(item)?;
                encoded_arr.push(encoded_item);
            }
            Ok(BfeValue::Array(encoded_arr))
        }
        Value::Object(v) => {
            let mut encoded_obj = IndexMap::new();
            for (key, val) in v {
                let encoded_value = encode(val)?;
                encoded_obj.insert(key.to_string(), encoded_value);
            }
            Ok(BfeValue::Object(encoded_obj))
        }
        Value::String(v) => {
            let encoded_str;
            if v.starts_with("ssb:") {
                encoded_str = encode_uri(v)?
            } else if v.starts_with('@') {
                encoded_str = encode_feed(v)?
            } else if v.starts_with('%') {
                encoded_str = encode_msg(v)?
            } else if v.starts_with('&') {
                encoded_str = encode_blob(v)?
            } else if v.ends_with(".sig.ed25519") {
                encoded_str = encode_sig(v)?
            } else if v.ends_with(".box2") || v.ends_with(".box") {
                encoded_str = encode_box(v)?
            } else {
                encoded_str = encode_string(v)?
            }
            Ok(BfeValue::Buffer(encoded_str))
        }
        Value::Bool(v) => {
            let encoded_bool = encode_bool(v)?;
            Ok(BfeValue::Buffer(encoded_bool))
        }
        Value::Number(v) => {
            if v.is_i64() {
                let int = v.as_i64().context("NoneError for `value.as_i64`")?;
                Ok(BfeValue::SignedInteger(int))
            } else if v.is_u64() {
                let int = v.as_u64().context("NoneError for `value.as_u64`")?;
                Ok(BfeValue::UnsignedInteger(int))
            } else {
                // the only other possible option is f64
                let float = v.as_f64().context("NoneError for `value.as_f64`")?;
                Ok(BfeValue::Float(float))
            }
        }
        Value::Null => Ok(BfeValue::Buffer(GENERIC_FORMATS["nil"].0.to_vec())),
    }
}

/// Take a blob ID as an encoded byte vector and return a decoded string representation.
pub fn decode_blob(blob_id: Vec<u8>) -> Result<String> {
    let blob_extension;
    if &blob_id[..2] == BLOB_FORMATS["classic"].0 {
        blob_extension = ".sha256"
    } else {
        return Err(anyhow!("Unknown blob ID: {:?}", blob_id));
    }

    let b64_data = base64::encode(&blob_id[2..]);
    let decoded_blob_id = format!("&{}{}", b64_data, blob_extension.to_string());

    Ok(decoded_blob_id)
}

/// Take a boolean key as an encoded byte vector and return a boolean value.
pub fn decode_bool(boolean: Vec<u8>) -> bool {
    boolean[2..] == [0x01]
}

/// Take a private box as an encoded byte vector and return a decoded string representation.
pub fn decode_box(box_vec: Vec<u8>) -> Result<String> {
    let box_extension;

    if &box_vec[..2] == ENCRYPTED_FORMATS["box1"].0 {
        // assign the suffix (`Some(suffix)` at tuple index 4)
        box_extension = ENCRYPTED_FORMATS["box1"].4.unwrap()
    } else if &box_vec[..2] == ENCRYPTED_FORMATS["box2"].0 {
        box_extension = ENCRYPTED_FORMATS["box2"].4.unwrap()
    } else {
        return Err(anyhow!("Unknown box: {:?}", box_vec));
    }

    let b64_data = base64::encode(&box_vec[2..]);
    let decoded_box = format!("{}{}", b64_data, box_extension.to_string());

    Ok(decoded_box)
}

/// Take a feed ID (key) as an encoded byte vector and return a decoded string representation.
pub fn decode_feed(feed_id: Vec<u8>) -> Result<String> {
    let feed_extension;
    if &feed_id[..2] == FEED_FORMATS["classic"].0 {
        feed_extension = ".ed25519"
    } else {
        return Err(anyhow!("Unknown feed ID: {:?}", feed_id));
    }

    // encode the last two bytes of the feed identity as base64
    let b64_data = base64::encode(&feed_id[2..]);
    let decoded_feed_id = format!("@{}{}", b64_data, feed_extension.to_string());

    Ok(decoded_feed_id)
}

/// Take a message ID as an encoded byte vector and return a decoded string representation.
pub fn decode_msg(msg_id: Vec<u8>) -> Result<Option<String>> {
    if msg_id.len() == 2 {
        return Ok(None);
    }
    let msg_extension;
    if &msg_id[..2] == MSG_FORMATS["classic"].0 {
        msg_extension = ".sha256"
    } else if &msg_id[..2] == MSG_FORMATS["cloaked"].0 {
        msg_extension = ".cloaked"
    } else {
        return Err(anyhow!("Unknown message ID: {:?}", msg_id));
    }

    let b64_data = base64::encode(&msg_id[2..]);
    let decoded_msg_id = format!("%{}{}", b64_data, msg_extension.to_string());

    Ok(Some(decoded_msg_id))
}

/// Take a signature as an encoded byte vector and return a string.
pub fn decode_sig(sig: Vec<u8>) -> Result<String> {
    let b64_data = base64::encode(&sig[2..]);
    let decoded_sig = format!("{}.sig.ed25519", b64_data);

    Ok(decoded_sig)
}

/// Take a string as an encoded byte vector and return a string.
pub fn decode_string(string: Vec<u8>) -> Result<String> {
    let decoded_string = str::from_utf8(&string[2..])
        .with_context(|| format!("The string bytes are not valid UTF-8: {:?}", string))?
        .to_owned();

    Ok(decoded_string)
}

/// Take an SSB URI as an encoded byte vector and return a string.
pub fn decode_uri(uri: Vec<u8>) -> Result<String> {
    let uri_type;
    let uri_format;

    if &uri[..2] == FEED_FORMATS["gabbygrove-v1"].0 {
        uri_type = "feed";
        uri_format = "gabbygrove-v1";
    } else if &uri[..2] == FEED_FORMATS["bendybutt-v1"].0 {
        uri_type = "feed";
        uri_format = "bendybutt-v1";
    } else if &uri[..2] == MSG_FORMATS["gabbygrove-v1"].0 {
        uri_type = "message";
        uri_format = "gabbygrove-v1";
    } else if &uri[..2] == MSG_FORMATS["bendybutt-v1"].0 {
        uri_type = "message";
        uri_format = "bendybutt-v1";
    } else {
        return Err(anyhow!(
            "Unknown type-format {:?} for encoded URI: {:?}",
            &uri[..2],
            uri
        ));
    }

    let b64_data = base64::encode(&uri[2..]);
    let parts = Parts(uri_type.to_string(), uri_format.to_string(), b64_data);
    let decoded_uri = ssb_uri_rs::compose_uri(parts)?;

    Ok(decoded_uri)
}

/// Take a BFE value, match on the value type(s) and call the appropriate decoder(s).
///
/// Returns the decoded value in the form of a `Result<Value>`.
pub fn decode(value: &BfeValue) -> Result<Value> {
    match value {
        BfeValue::Array(arr) => {
            let mut decoded_arr = Vec::new();
            for item in arr {
                let decoded_item = decode(item)?;
                decoded_arr.push(decoded_item);
            }
            Ok(json!(decoded_arr))
        }
        BfeValue::Buffer(buf) => {
            let mut decoded_buf = None;
            if buf.len() < 2 {
                return Err(anyhow!(
                    "Buffer is missing first two type&format fields: {:?}",
                    buf
                ));
            // uris (match on type-format code at tuple index `0`)
            } else if &buf[..2] == FEED_FORMATS["gabbygrove-v1"].0
                || &buf[..2] == FEED_FORMATS["bendybutt-v1"].0
                || &buf[..2] == MSG_FORMATS["gabbygrove-v1"].0
                || &buf[..2] == MSG_FORMATS["bendybutt-v1"].0
            {
                decoded_buf = Some(decode_uri(buf.to_vec())?)
            // generic types
            } else if &buf[..2] == GENERIC_FORMATS["string-UTF8"].0 {
                decoded_buf = Some(decode_string(buf.to_vec())?)
            } else if &buf[..2] == GENERIC_FORMATS["boolean"].0 {
                return Ok(json!(decode_bool(buf.to_vec())));
            } else if &buf[..2] == GENERIC_FORMATS["nil"].0 {
                decoded_buf = None
            // classic types
            } else if &buf[..1] == TYPES["feed"].0 {
                decoded_buf = Some(decode_feed(buf.to_vec())?)
            } else if &buf[..1] == TYPES["message"].0 {
                // ignore the None return type (msg.len() == 2)
                if let Some(val) = decode_msg(buf.to_vec())? {
                    decoded_buf = Some(val)
                }
            } else if &buf[..1] == TYPES["blob"].0 {
                decoded_buf = Some(decode_blob(buf.to_vec())?)
            } else if &buf[..1] == TYPES["encrypted"].0 {
                decoded_buf = Some(decode_box(buf.to_vec())?)
            } else if &buf[..2] == SIGNATURE_FORMATS["msg-ed25519"].0 {
                decoded_buf = Some(decode_sig(buf.to_vec())?)
            } else {
                // no match: return the buffer value without decoding
                return Ok(json!({ "Buffer": buf }));
            }
            Ok(json!(decoded_buf))
        }
        BfeValue::Object(obj) => {
            let mut decoded_obj = IndexMap::new();
            for (k, v) in obj {
                let decoded_value = decode(v)?;
                decoded_obj.insert(k.to_string(), decoded_value);
            }
            Ok(json!(decoded_obj))
        }
        BfeValue::Float(float) => Ok(json!(float)),
        BfeValue::SignedInteger(int) => Ok(json!(int)),
        BfeValue::UnsignedInteger(int) => Ok(json!(int)),
    }
}

#[cfg(test)]
mod tests {
    use crate::data::*;
    use crate::BfeValue;
    use crate::*;

    use serde_json::json;

    #[test]
    fn get_box_type_matches_box1() {
        let result = get_box_type(BOX_1);
        assert!(result.is_ok());
        let result_code = result.unwrap();
        assert_eq!(result_code, ENCRYPTED_FORMATS["box1"].0);
    }

    #[test]
    fn get_box_type_matches_box2() {
        let result = get_box_type(BOX_2);
        assert!(result.is_ok());
        let result_code = result.unwrap();
        assert_eq!(result_code, ENCRYPTED_FORMATS["box2"].0);
    }

    #[test]
    fn get_feed_type_matches_classic() {
        let result = get_feed_type(CLASSIC_FEED);
        assert!(result.is_ok());
        let result_code = result.unwrap();
        assert_eq!(result_code, FEED_FORMATS["classic"].0);
    }

    #[test]
    fn get_feed_type_matches_unknown() {
        let result = get_feed_type("@what.is_this-v1");
        assert!(result.is_err());
    }

    #[test]
    fn get_msg_type_matches_classic() {
        let result = get_msg_type(CLASSIC_MSG);
        assert!(result.is_ok());
        let result_code = result.unwrap();
        assert_eq!(result_code, MSG_FORMATS["classic"].0);
    }

    #[test]
    fn get_msg_type_matches_unknown() {
        let result = get_msg_type("%what.is_this-v1");
        assert!(result.is_err());
    }

    #[test]
    fn encode_and_decode_blob_works() {
        let encoded = encode_blob(BLOB);
        assert!(encoded.is_ok());
        let encoded_value = encoded.unwrap();
        assert_eq!(&encoded_value[..2], BLOB_FORMATS["classic"].0);
        let decoded = decode_blob(encoded_value);
        assert!(decoded.is_ok());
        let decoded_value = decoded.unwrap();
        assert_eq!(BLOB, decoded_value);
    }

    #[test]
    fn encode_and_decode_bool_works() {
        let encoded = encode_bool(&true);
        assert!(encoded.is_ok());
        let encoded_value = encoded.unwrap();
        let expected = [GENERIC_FORMATS["boolean"].0, BOOL_TRUE].concat();
        assert_eq!(encoded_value, expected);
        let decoded = decode_bool(encoded_value);
        assert_eq!(true, decoded);
    }

    #[test]
    fn encode_and_decode_box_works() {
        let encoded = encode_box(BOX_1);
        assert!(encoded.is_ok());
        let encoded_value = encoded.unwrap();
        assert_eq!(&encoded_value[..2], ENCRYPTED_FORMATS["box1"].0);
        let decoded = decode_box(encoded_value);
        assert!(decoded.is_ok());
        let decoded_value = decoded.unwrap();
        assert_eq!(BOX_1, decoded_value);
    }

    #[test]
    fn encode_and_decode_box2_works() {
        let encoded = encode_box(BOX_2);
        assert!(encoded.is_ok());
        let encoded_value = encoded.unwrap();
        assert_eq!(&encoded_value[..2], ENCRYPTED_FORMATS["box2"].0);
        let decoded = decode_box(encoded_value);
        assert!(decoded.is_ok());
        let decoded_value = decoded.unwrap();
        assert_eq!(BOX_2, decoded_value);
    }

    #[test]
    fn encode_and_decode_bb_feed_uri_works() {
        let encoded = encode_uri(BB_FEED_URI);
        assert!(encoded.is_ok());
        let encoded_value = encoded.unwrap();
        assert_eq!(&encoded_value[..2], &[0x00, 0x03]);
        let decoded = decode_uri(encoded_value);
        assert!(decoded.is_ok());
        let decoded_value = decoded.unwrap();
        assert_eq!(BB_FEED_URI, decoded_value);
    }

    #[test]
    fn encode_and_decode_gg_feed_uri_works() {
        let encoded = encode_uri(GG_FEED_URI);
        assert!(encoded.is_ok());
        let encoded_value = encoded.unwrap();
        assert_eq!(&encoded_value[..2], &[0x00, 0x01]);
        let decoded = decode_uri(encoded_value);
        assert!(decoded.is_ok());
        let decoded_value = decoded.unwrap();
        assert_eq!(GG_FEED_URI, decoded_value);
    }

    #[test]
    fn encode_and_decode_classic_msg_works() {
        let encoded = encode_msg(CLASSIC_MSG);
        assert!(encoded.is_ok());
        let encoded_value = encoded.unwrap();
        let expected = vec![
            1, 0, 71, 200, 94, 171, 251, 80, 163, 17, 8, 62, 69, 159, 208, 172, 103, 214, 112, 166,
            252, 43, 49, 27, 96, 131, 165, 70, 39, 2, 247, 91, 93, 143,
        ];
        assert_eq!(expected, encoded_value);
        let decoded = decode_msg(encoded_value);
        assert!(decoded.is_ok());
        let decoded_option = decoded.unwrap();
        assert!(decoded_option.is_some());
        let decoded_value = decoded_option.unwrap();
        assert_eq!(CLASSIC_MSG, decoded_value);
    }

    #[test]
    fn encode_and_decode_bb_msg_uri_works() {
        let encoded = encode_uri(BB_MSG_URI);
        assert!(encoded.is_ok());
        let encoded_value = encoded.unwrap();
        assert_eq!(&encoded_value[..2], &[0x01, 0x04]);
        let decoded = decode_uri(encoded_value);
        assert!(decoded.is_ok());
        let decoded_value = decoded.unwrap();
        assert_eq!(BB_MSG_URI, decoded_value);
    }

    #[test]
    fn encode_and_decode_gg_msg_works() {
        let encoded = encode_uri(GG_MSG_URI);
        assert!(encoded.is_ok());
        let encoded_value = encoded.unwrap();
        assert_eq!(&encoded_value[..2], &[0x01, 0x01]);
        let decoded = decode_uri(encoded_value);
        assert!(decoded.is_ok());
        let decoded_value = decoded.unwrap();
        assert_eq!(GG_MSG_URI, decoded_value);
    }

    #[test]
    fn encode_and_decode_object_works() {
        let v = json!({
            "feed": CLASSIC_FEED,
            "sig": SIG,
            "blob": BLOB,
            "backups": true,
            "recurse": [null, "thing", false]
        });
        let encoded = encode(&v);
        assert!(encoded.is_ok());
        let encoded_value = encoded.unwrap();
        let decoded = decode(&encoded_value);
        assert!(decoded.is_ok());
        let decoded_value = decoded.unwrap();
        assert_eq!(v, decoded_value);
    }

    #[test]
    fn encode_and_decode_sig_works() {
        let encoded = encode_sig(SIG);
        assert!(encoded.is_ok());
        let encoded_value = encoded.unwrap();
        let expected = vec![
            4, 0, 158, 70, 56, 90, 201, 253, 125, 234, 44, 198, 245, 251, 110, 146, 202, 236, 236,
            99, 117, 42, 240, 234, 4, 139, 242, 203, 167, 214, 125, 147, 48, 181, 202, 201, 38, 10,
            244, 190, 98, 181, 84, 39, 87, 105, 208, 81, 203, 69, 178, 181, 14, 107, 104, 172, 180,
            61, 175, 14, 77, 65, 210, 224, 12, 5,
        ];
        assert_eq!(expected, encoded_value);
        let decoded = decode_sig(encoded_value);
        assert!(decoded.is_ok());
        let decoded_value = decoded.unwrap();
        assert_eq!(SIG, decoded_value);
    }

    #[test]
    fn encode_and_decode_string_works() {
        let encoded = encode_string("golden ripples in the meshwork");
        assert!(encoded.is_ok());
        let encoded_value = encoded.unwrap();
        let expected = vec![
            6, 0, 103, 111, 108, 100, 101, 110, 32, 114, 105, 112, 112, 108, 101, 115, 32, 105,
            110, 32, 116, 104, 101, 32, 109, 101, 115, 104, 119, 111, 114, 107,
        ];
        assert_eq!(expected, encoded_value);
        let decoded = decode_string(encoded_value);
        assert!(decoded.is_ok());
        let decoded_value = decoded.unwrap();
        assert_eq!("golden ripples in the meshwork", decoded_value);
    }

    #[test]
    fn encode_value_array_works() {
        let v = json!(["ichneumonid", "coleopteran"]);
        let result = encode(&v);
        assert!(result.is_ok());
    }

    #[test]
    fn encode_value_bool_works() {
        let v = json!(true);
        let result = encode(&v);
        assert!(result.is_ok());
    }

    #[test]
    fn encode_value_null_works() {
        let v = json!(null);
        let encoded = encode(&v);
        assert!(encoded.is_ok());
        let encoded_value = encoded.unwrap();
        assert_eq!(BfeValue::Buffer([6, 2].to_vec()), encoded_value);
    }

    #[test]
    fn encode_value_string_works() {
        let v = json!("pyrophilous fungi");
        let result = encode(&v);
        assert!(result.is_ok());
    }

    #[test]
    fn decode_returns_unmatched_buffer() {
        let buf = BfeValue::Buffer([7, 7, 7].to_vec());
        let decoded = decode(&buf);
        assert!(decoded.is_ok());
        let json_buf = json!(buf);
        let decoded_value = decoded.unwrap();
        assert_eq!(json_buf, decoded_value);
    }

    const BLOB: &str = "&S7+CwHM6dZ9si5Vn4ftpk/l/ldbRMqzzJos+spZbWf4=.sha256";
    const BOX_1: &str = "siZEm1zFx1icq0SrEynGDpNRmJCXMxTB3iEteXFn+IhJH8WhMbT8tp9qOIaFkIYcdOyerSon6RK0l4RE1ZdDh/3lcGZSdP0Ljq59qsdqlf2ngwbIbV9AWdPRrPsoVZBV6RhI+YcVTloWWP5aauu1hZKjcm62ezLBTQ3EmFPYtDuwsOFkx9/7FP97ljhj67CwvlGzuiWp6FNICHbt5kOCxs9H0k6Tr8JJVdaJtJ2pqkX4p0ECMuEuYxCYbh3FpncCqlNZJXb0dj3iSsfsMNWTJLDqfkqJKH1jBVfxDL6+xAXBDS+E4F2hD4y9gRDZEej99uVBQWlbxr5eCRV+VbfBGYxwoAYtqux6rg3jBabImKKinBwHShEP5F/+wlb9IxQn4swyOgyv+UKx/jbx+91Ayso5bnNPZMpwRRX5p5DbpK1BnryeVJhktMgFqgni1g0lHyU8sQ2QzwZgXGw7dfYoamkqK4D24NOLnUoHuVuhd7Q5SxZWSAO6wpDa4nrODePoJdl328pbMwCoQlUNeHINmKxh/o/oCNbgXitn4oN3kSVEg/umdgwwI94gmZUjiYwP1v7HA7dI.box";
    const BOX_2: &str = "WQyfhDDHQ1gH34uppHbj8SldRu8hD2764gQ6TAhaVp6R01EMBnJQj5ewD5F+UT5NwvV91uU8q5XCjuvcP4ihCJ0RtX8HjKyN+tDKP5gKB3UZo/eO/rP5CcPGoIG7pcLBsd3DQbZLfTnb/iqECEji9gclNcGENTS2u6aATwbQ4uQ7RzIAKKT2NfC2qk86p/gXC2owDFAazuPlQTT8DMNvO8G52gb48a75CGKsDAevrC//Bz38VFxwUiTKzRWaxCbTK9knj39u3qoCP9VLyyRqITgNwvlGLP7ndchTyBiO0TPNkb9PAOenw5WBjyWhA61hpG+VkKpkaysBVGjXYv8OpV1HGbs87TI79uT7JrNV4wEZiwqGknwmCi5B2gbd7tav8yDXsK5yQgDncHQjZotsBFX2adP7Jli9WmvV3xX5lL3kBNKV0ZiE/DZUgB2m1OXvCjNI4fuZhnpZpEQi9coO+icrirKiH/UA8TS9HI72cIbkEJVxOTnKnsgr3Qc/5HhtRS17a54ymVmBsnpP+KqqCqKLN50TInb7qoUlvQ2nw07xX3Ig9usLb8Ik8U8XMb6SLqACxlZN/qW4EJzxVetoIk84AU1yLInK6v9dzfsewRYBXW8+lYbyxVNuIIK4pKYsx2WbjuJyZHgjgbCdGf/kjqP5rDs4zwqj2lmkO70PoEUrcSi46J2hkqtcrd1yl+F3/BDwFlxAXH+x4+LhmT7g+BSgzRUbWvCyeB+HJaoao6g4K/Fs8HxnbVB1zW761OQJaQnV86ZThkvUjXh2SEBlBd+D94eUCqIJkjI7RLt+D/0gxg/D7u1Zq14UxRijZryB51An7GdXtEc2xhU+Bh/aPmKmMZ9D/ArdglSlnVUD8OIBVVw5jtooGlhxbOFHM4N5SoAO/yWPcbcuQz7t4SPij358rY574DLBGZEPCrS6KPpnrlqlnZK4f6/+9zv3hfzNTXVvJtxZL/rvmNvbgh7LpMnSqjnsXqm86a3GXeVWD83TdCnL1oPqEi/8RItTrjy01DmVhUoV6t12STP4mHb8RjR+/ks+7lowfV3HQ13n6if0g0/u+Bzv6XXOX6iePPOHA3lFv2MSPKf9JZ0uQiqajR03YkNE8YnSTYu0Io1cGPZ/lWBp2tyWtwFmGtqw/9+O165tJhrdU2EXJ4T/XP136WpLD2+vtYsx3Xr5lfeD12/g+I/6jwduqTuHpst2tqvcSWoZ4DAWcpcKJ1mUbJU3/mLAYGwWb3XuqMOgJOLoztAwd5xFzUZD1MnR/iyYoZ2weYTSOz3OKR3cJyCjxBhIGaX5xpAc61K1dXNfERBJr9TS0mL2578dd5AauE6Ksn6YlGxNJIVC3VpdAtRbVHNX1g==.box2";
    const BB_FEED_URI: &str = "ssb:feed/bendybutt-v1/6CAxOI3f-LUOVrbAl0IemqiS7ATpQvr9Mdw9LC4-Uv0=";
    const CLASSIC_FEED: &str = "@d/zDvFswFbQaYJc03i47C9CgDev+/A8QQSfG5l/SEfw=.ed25519";
    const GG_FEED_URI: &str = "ssb:feed/gabbygrove-v1/FY5OG311W4j_KPh8H9B2MZt4WSziy_p-ABkKERJdujQ=";
    const BB_MSG_URI: &str =
        "ssb:message/bendybutt-v1/HZVnEzm0NgoSVfG0Hx4gMFbMMHhFvhJsG2zK_pijYII=";
    const CLASSIC_MSG: &str = "%R8heq/tQoxEIPkWf0Kxn1nCm/CsxG2CDpUYnAvdbXY8=.sha256";
    const GG_MSG_URI: &str =
        "ssb:message/gabbygrove-v1/QibgMEFVrupoOpiILKVoNXnhzdVQVZf7dkmL9MSXO5g=";
    const SIG: &str = "nkY4Wsn9feosxvX7bpLK7OxjdSrw6gSL8sun1n2TMLXKySYK9L5itVQnV2nQUctFsrUOa2istD2vDk1B0uAMBQ==.sig.ed25519";
}
