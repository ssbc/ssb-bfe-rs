//! # ssb-bfe-rs
//!
//! Binary Field Encodings (BFE) for Secure Scuttlebutt (SSB).
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
//!     "author": "@6CAxOI3f+LUOVrbAl0IemqiS7ATpQvr9Mdw9LC4+Uv0=.bbfeed-v1",
//!     "previous": "%R8heq/tQoxEIPkWf0Kxn1nCm/CsxG2CDpUYnAvdbXY8=.bbmsg-v1"
//! });
//!
//! let encoded = ssb_bfe_rs::encode(&value);
//! let encoded_value = encoded.unwrap();
//! println!("{:X?}", encoded_value);
//!
//! // Object({"author": Buffer([0, 3, E8, 20, 31, 38, 8D, DF, F8, B5, E, 56, B6, C0, 97, 42, 1E, 9A, A8, 92, EC, 4, E9, 42, FA, FD, 31, DC, 3D, 2C, 2E, 3E, 52, FD]), "previous": Buffer([1, 4, 47, C8, 5E, AB, FB, 50, A3, 11, 8, 3E, 45, 9F, D0, AC, 67, D6, 70, A6, FC, 2B, 31, 1B, 60, 83, A5, 46, 27, 2, F7, 5B, 5D, 8F])})
//!
//! let decoded = ssb_bfe_rs::decode(&encoded_value);
//! let decoded_value = decoded.unwrap();
//! println!("{:?}", decoded_value);
//!
//! // Object({"author": String("@6CAxOI3f+LUOVrbAl0IemqiS7ATpQvr9Mdw9LC4+Uv0=.bbfeed-v1"), "previous": String("%R8heq/tQoxEIPkWf0Kxn1nCm/CsxG2CDpUYnAvdbXY8=.bbmsg-v1")})
//! ```
use std::str;

use anyhow::{anyhow, Context, Result};
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

/* The naming convention used for constant types follows the TFD spec (also known as TFK):
 * "T" - Type byte
 * "F" - Format byte
 * "D" - Data byte
 */

/// Encoded value for feed type.
pub const FEED_T: &[u8] = &[0x00];
/// Encoded value for classic (legacy) feed type-format.
pub const CLASSIC_FEED_TF: &[u8] = &[0x00, 0x00];
/// Encoded value for Gabby Grove (GG) feed type-format.
pub const GABBYGR_FEED_TF: &[u8] = &[0x00, 0x01];
/// Encoded value for Bendy Butt (BB) feed type-format.
pub const BENDYBT_FEED_TF: &[u8] = &[0x00, 0x03];

/// Encoded value for message type.
pub const MSG_T: &[u8] = &[0x01];
/// Encoded value for classic (legacy) message type-format.
pub const CLASSIC_MSG_TF: &[u8] = &[0x01, 0x00];
/// Encoded value for Gabby Grove (GG) message type-format.
pub const GABBYGR_MSG_TF: &[u8] = &[0x01, 0x01];
/// Encoded value for Bendy Butt (BB) message type-format.
pub const BENDYBT_MSG_TF: &[u8] = &[0x01, 0x04];

/// Encoded value for blob type.
pub const BLOB_T: &[u8] = &[0x02];
/// Encoded value for classic blob type-format.
pub const CLASSIC_BLOB_TF: &[u8] = &[0x02, 0x00];

/// Encoded value for signature type-format.
pub const SIGNATURE_TF: &[u8] = &[0x04, 0x00];

/// Encoded value for box type (encrypted data).
pub const BOX_T: &[u8] = &[0x05];
/// Encoded value for box1 type-format.
pub const BOX1_TF: &[u8] = &[0x05, 0x00];
/// Encoded value for box2 type-format.
pub const BOX2_TF: &[u8] = &[0x05, 0x01];

/// Encoded value for string type-format.
pub const STRING_TF: &[u8] = &[0x06, 0x00];
/// Encoded value for boolean type-format.
pub const BOOL_TF: &[u8] = &[0x06, 0x01];
/// Encoded value for boolean true value.
pub const BOOL_TRUE: &[u8] = &[0x01];
/// Encoded value for boolean false value.
pub const BOOL_FALSE: &[u8] = &[0x00];
/// Encoded value for nil type-format.
pub const NIL_TF: &[u8] = &[0x06, 0x02];
/// Encoded value for nil type-format-data.
pub const NIL_TFD: &[u8] = NIL_TF;

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
    let blob_type;
    if blob_id.ends_with(".sha256") {
        blob_type = CLASSIC_BLOB_TF
    } else {
        return Err(anyhow!("Unknown blob ID: {}", blob_id));
    };

    Ok(blob_type.to_vec())
}

/// Take a box as a string and return the encoded bytes representing the box type-format.
// Note: box refers to an SSB `private box` and not a Rust `Box` (pointer type)
pub fn get_box_type(boxed_str: &str) -> Result<Vec<u8>> {
    let box_type;
    if boxed_str.ends_with(".box") {
        box_type = BOX1_TF
    } else if boxed_str.ends_with(".box2") {
        box_type = BOX2_TF
    } else {
        return Err(anyhow!("Unknown boxed string: {}", boxed_str));
    };

    Ok(box_type.to_vec())
}

/// Take a feed ID (key) as a string and return the encoded bytes representing the feed type-format.
pub fn get_feed_type(feed_id: &str) -> Result<Vec<u8>> {
    let feed_type;
    if feed_id.ends_with(".ed25519") {
        feed_type = CLASSIC_FEED_TF
    } else if feed_id.ends_with(".bbfeed-v1") {
        feed_type = BENDYBT_FEED_TF
    } else if feed_id.ends_with(".ggfeed-v1") {
        feed_type = GABBYGR_FEED_TF
    } else {
        return Err(anyhow!("Unknown feed format: {}", feed_id));
    };

    Ok(feed_type.to_vec())
}

/// Take a message ID as a string and return the encoded bytes representing the message type-format.
pub fn get_msg_type(msg_id: &str) -> Result<Vec<u8>> {
    let msg_type;
    if msg_id.ends_with(".sha256") {
        msg_type = CLASSIC_MSG_TF
    } else if msg_id.ends_with(".bbmsg-v1") {
        msg_type = BENDYBT_MSG_TF
    } else if msg_id.ends_with(".ggmsg-v1") {
        msg_type = GABBYGR_MSG_TF
    } else {
        return Err(anyhow!("Unknown message ID: {}", msg_id));
    };

    Ok(msg_type.to_vec())
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
pub fn encode_bool(boolean: bool) -> Result<Vec<u8>> {
    let bool_vec = match boolean {
        true => [BOOL_TF, BOOL_TRUE].concat(),
        false => [BOOL_TF, BOOL_FALSE].concat(),
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
    let mut encoded_sig = SIGNATURE_TF.to_vec();
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
    let encoded_string = [STRING_TF, string.as_bytes()].concat();

    Ok(encoded_string)
}

/// Take a JSON value, match on the value type(s) and call the appropriate encoder(s).
///
/// Returns the encoded value in the form of a `Result<BfeValue>`.
pub fn encode(value: &Value) -> Result<BfeValue> {
    if value.is_array() {
        let value_arr = value.as_array().context("NoneError for `value.as_array`")?;
        let mut encoded_arr = Vec::new();
        for item in value_arr {
            let encoded_item = encode(item)?;
            encoded_arr.push(encoded_item);
        }
        Ok(BfeValue::Array(encoded_arr))
    } else if value.is_null() {
        Ok(BfeValue::Buffer(NIL_TFD.to_vec()))
    } else if !value.is_array() && value.is_object() && !value.is_null() {
        let value_obj = value
            .as_object()
            .context("NoneError for `value.as_object`")?;
        let mut encoded_obj = IndexMap::new();
        for (k, v) in value_obj {
            let encoded_value = encode(v)?;
            encoded_obj.insert(k.to_string(), encoded_value);
        }
        Ok(BfeValue::Object(encoded_obj))
    } else if value.is_string() {
        let value_str = value.as_str().context("NoneError for `value.as_str`")?;
        let encoded_str;
        if value_str.starts_with('@') {
            encoded_str = encode_feed(value_str)?
        } else if value_str.starts_with('%') {
            encoded_str = encode_msg(value_str)?
        } else if value_str.starts_with('&') {
            encoded_str = encode_blob(value_str)?
        } else if value_str.ends_with(".sig.ed25519") {
            encoded_str = encode_sig(value_str)?
        } else if value_str.ends_with(".box2") || value_str.ends_with(".box") {
            encoded_str = encode_box(value_str)?
        } else {
            encoded_str = encode_string(value_str)?
        }
        Ok(BfeValue::Buffer(encoded_str))
    } else if value.is_boolean() {
        let value_bool = value.as_bool().context("NoneError for `value.as_bool`")?;
        let encoded_bool = encode_bool(value_bool)?;
        Ok(BfeValue::Buffer(encoded_bool))
    } else if value.is_i64() {
        let int = value.as_i64().context("NoneError for `value.as_i64`")?;
        Ok(BfeValue::SignedInteger(int))
    } else if value.is_u64() {
        let int = value.as_u64().context("NoneError for `value.as_u64`")?;
        Ok(BfeValue::UnsignedInteger(int))
    } else if value.is_f64() {
        let float = value.as_f64().context("NoneError for `value.as_f64`")?;
        Ok(BfeValue::Float(float))
    } else {
        Err(anyhow!("Not encoding unknown value: {}", value))
    }
}

/// Take a blob ID as an encoded byte vector and return a decoded string representation.
pub fn decode_blob(blob_id: Vec<u8>) -> Result<String> {
    let blob_extension;
    if &blob_id[..2] == CLASSIC_BLOB_TF {
        blob_extension = ".sha256"
    } else {
        return Err(anyhow!("Unknown blob ID: {:?}", blob_id));
    }

    let b64_type = base64::encode(&blob_id[2..]);
    let decoded_blob_id = format!("&{}{}", b64_type, blob_extension.to_string());

    Ok(decoded_blob_id)
}

/// Take a boolean key as an encoded byte vector and return a boolean value.
pub fn decode_bool(boolean: Vec<u8>) -> bool {
    boolean[2..] == [0x01]
}

/// Take a private box as an encoded byte vector and return a decoded string representation.
pub fn decode_box(box_vec: Vec<u8>) -> Result<String> {
    let box_extension;
    if &box_vec[..2] == BOX1_TF {
        box_extension = ".box"
    } else if &box_vec[..2] == BOX2_TF {
        box_extension = ".box2"
    } else {
        return Err(anyhow!("Unknown box: {:?}", box_vec));
    }

    let b64_type = base64::encode(&box_vec[2..]);
    let decoded_box = format!("{}{}", b64_type, box_extension.to_string());

    Ok(decoded_box)
}

/// Take a feed ID (key) as an encoded byte vector and return a decoded string representation.
pub fn decode_feed(feed_id: Vec<u8>) -> Result<String> {
    let feed_extension;
    if &feed_id[..2] == CLASSIC_FEED_TF {
        feed_extension = ".ed25519"
    } else if &feed_id[..2] == BENDYBT_FEED_TF {
        feed_extension = ".bbfeed-v1"
    } else if &feed_id[..2] == GABBYGR_FEED_TF {
        feed_extension = ".ggfeed-v1"
    } else {
        return Err(anyhow!("Unknown feed ID: {:?}", feed_id));
    }

    // encode the last two bytes of the feed identity as base64
    let b64_type = base64::encode(&feed_id[2..]);
    let decoded_feed_id = format!("@{}{}", b64_type, feed_extension.to_string());

    Ok(decoded_feed_id)
}

/// Take a message ID as an encoded byte vector and return a decoded string representation.
pub fn decode_msg(msg_id: Vec<u8>) -> Result<Option<String>> {
    if msg_id.len() == 2 {
        return Ok(None);
    }
    let msg_extension;
    if &msg_id[..2] == CLASSIC_MSG_TF {
        msg_extension = ".sha256"
    } else if &msg_id[..2] == BENDYBT_MSG_TF {
        msg_extension = ".bbmsg-v1"
    } else if &msg_id[..2] == GABBYGR_MSG_TF {
        msg_extension = ".ggmsg-v1"
    } else {
        return Err(anyhow!("Unknown message ID: {:?}", msg_id));
    }

    let b64_type = base64::encode(&msg_id[2..]);
    let decoded_msg_id = format!("%{}{}", b64_type, msg_extension.to_string());

    Ok(Some(decoded_msg_id))
}

/// Take a signature as an encoded byte vector and return a string.
pub fn decode_sig(sig: Vec<u8>) -> Result<String> {
    let b64_type = base64::encode(&sig[2..]);
    let decoded_sig = format!("{}.sig.ed25519", b64_type);

    Ok(decoded_sig)
}

/// Take a string as an encoded byte vector and return a string.
pub fn decode_string(string: Vec<u8>) -> Result<String> {
    let decoded_string = str::from_utf8(&string[2..])
        .with_context(|| format!("The string bytes are not valid UTF-8: {:?}", string))?
        .to_owned();

    Ok(decoded_string)
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
            } else if &buf[..2] == STRING_TF {
                decoded_buf = Some(decode_string(buf.to_vec())?)
            } else if &buf[..2] == BOOL_TF {
                return Ok(json!(decode_bool(buf.to_vec())));
            } else if &buf[..2] == NIL_TF {
                decoded_buf = None
            } else if &buf[..1] == FEED_T {
                decoded_buf = Some(decode_feed(buf.to_vec())?)
            } else if &buf[..1] == MSG_T {
                // ignore the None return type (msg.len() == 2)
                if let Some(val) = decode_msg(buf.to_vec())? {
                    decoded_buf = Some(val)
                }
            } else if &buf[..1] == BLOB_T {
                decoded_buf = Some(decode_blob(buf.to_vec())?)
            } else if &buf[..1] == BOX_T {
                decoded_buf = Some(decode_box(buf.to_vec())?)
            } else if &buf[..2] == SIGNATURE_TF {
                decoded_buf = Some(decode_sig(buf.to_vec())?)
            } else {
                let buffer_str = str::from_utf8(buf)
                    .with_context(|| format!("The string bytes are not valid UTF-8: {:?}", buf))?;
                decoded_buf = Some(base64::encode(buffer_str))
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
    use crate::BfeValue;
    use crate::{
        decode, decode_bool, decode_box, decode_feed, decode_msg, decode_sig, decode_string,
        encode, encode_bool, encode_box, encode_feed, encode_msg, encode_sig, encode_string,
        get_box_type, get_feed_type, get_msg_type,
    };
    use crate::{
        BENDYBT_FEED_TF, BENDYBT_MSG_TF, BOX1_TF, BOX2_TF, CLASSIC_FEED_TF, CLASSIC_MSG_TF,
        GABBYGR_FEED_TF, GABBYGR_MSG_TF,
    };
    use serde_json::json;

    #[test]
    fn get_box_type_matches_box1() {
        let result = get_box_type(BOX_1);
        assert!(result.is_ok());
        let result_code = result.unwrap();
        assert_eq!(result_code, BOX1_TF);
    }

    #[test]
    fn get_box_type_matches_box2() {
        let result = get_box_type(BOX_2);
        assert!(result.is_ok());
        let result_code = result.unwrap();
        assert_eq!(result_code, BOX2_TF);
    }

    #[test]
    fn get_feed_type_matches_bendy_butt() {
        let result = get_feed_type(BB_FEED);
        assert!(result.is_ok());
        let result_code = result.unwrap();
        assert_eq!(result_code, BENDYBT_FEED_TF);
    }

    #[test]
    fn get_feed_type_matches_classic() {
        let result = get_feed_type(CLASSIC_FEED);
        assert!(result.is_ok());
        let result_code = result.unwrap();
        assert_eq!(result_code, CLASSIC_FEED_TF);
    }

    #[test]
    fn get_feed_type_matches_gabby_grove() {
        let result = get_feed_type(GG_FEED);
        assert!(result.is_ok());
        let result_code = result.unwrap();
        assert_eq!(result_code, GABBYGR_FEED_TF);
    }

    #[test]
    fn get_feed_type_matches_unknown() {
        let result = get_feed_type("@what.is_this-v1");
        assert!(result.is_err());
    }

    #[test]
    fn get_msg_type_matches_bendy_butt() {
        let result = get_msg_type(BB_MSG);
        assert!(result.is_ok());
        let result_code = result.unwrap();
        assert_eq!(result_code, BENDYBT_MSG_TF);
    }

    #[test]
    fn get_msg_type_matches_classic() {
        let result = get_msg_type(CLASSIC_MSG);
        assert!(result.is_ok());
        let result_code = result.unwrap();
        assert_eq!(result_code, CLASSIC_MSG_TF);
    }

    #[test]
    fn get_msg_type_matches_gabby_grove() {
        let result = get_msg_type(GG_MSG);
        assert!(result.is_ok());
        let result_code = result.unwrap();
        assert_eq!(result_code, GABBYGR_MSG_TF);
    }

    #[test]
    fn get_msg_type_matches_unknown() {
        let result = get_msg_type("%what.is_this-v1");
        assert!(result.is_err());
    }

    #[test]
    fn encode_and_decode_bool_works() {
        let encoded = encode_bool(true);
        assert!(encoded.is_ok());
        let encoded_value = encoded.unwrap();
        let expected = vec![6, 1, 1];
        assert_eq!(expected, encoded_value);
        let decoded = decode_bool(encoded_value);
        assert_eq!(true, decoded);
    }

    #[test]
    fn encode_and_decode_box_works() {
        let encoded = encode_box(BOX_1);
        assert!(encoded.is_ok());
        let encoded_value = encoded.unwrap();
        let expected = vec![5, 0];
        assert_eq!(expected, &encoded_value[..2]);
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
        let expected = vec![5, 1];
        assert_eq!(expected, &encoded_value[..2]);
        let decoded = decode_box(encoded_value);
        assert!(decoded.is_ok());
        let decoded_value = decoded.unwrap();
        assert_eq!(BOX_2, decoded_value);
    }

    #[test]
    fn encode_and_decode_feed_works() {
        let encoded = encode_feed(BB_FEED);
        assert!(encoded.is_ok());
        let encoded_value = encoded.unwrap();
        let expected = vec![
            0, 3, 232, 32, 49, 56, 141, 223, 248, 181, 14, 86, 182, 192, 151, 66, 30, 154, 168,
            146, 236, 4, 233, 66, 250, 253, 49, 220, 61, 44, 46, 62, 82, 253,
        ];
        assert_eq!(expected, encoded_value);
        let decoded = decode_feed(encoded_value);
        assert!(decoded.is_ok());
        let decoded_value = decoded.unwrap();
        assert_eq!(BB_FEED, decoded_value);
    }

    #[test]
    fn encode_and_decode_msg_works() {
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
    fn encode_and_decode_object_works() {
        let v = json!({
            "feed": "@d/zDvFswFbQaYJc03i47C9CgDev+/A8QQSfG5l/SEfw=.ed25519",
            "sig": "nkY4Wsn9feosxvX7bpLK7OxjdSrw6gSL8sun1n2TMLXKySYK9L5itVQnV2nQUctFsrUOa2istD2vDk1B0uAMBQ==.sig.ed25519",
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

    const BOX_1: &str = "siZEm1zFx1icq0SrEynGDpNRmJCXMxTB3iEteXFn+IhJH8WhMbT8tp9qOIaFkIYcdOyerSon6RK0l4RE1ZdDh/3lcGZSdP0Ljq59qsdqlf2ngwbIbV9AWdPRrPsoVZBV6RhI+YcVTloWWP5aauu1hZKjcm62ezLBTQ3EmFPYtDuwsOFkx9/7FP97ljhj67CwvlGzuiWp6FNICHbt5kOCxs9H0k6Tr8JJVdaJtJ2pqkX4p0ECMuEuYxCYbh3FpncCqlNZJXb0dj3iSsfsMNWTJLDqfkqJKH1jBVfxDL6+xAXBDS+E4F2hD4y9gRDZEej99uVBQWlbxr5eCRV+VbfBGYxwoAYtqux6rg3jBabImKKinBwHShEP5F/+wlb9IxQn4swyOgyv+UKx/jbx+91Ayso5bnNPZMpwRRX5p5DbpK1BnryeVJhktMgFqgni1g0lHyU8sQ2QzwZgXGw7dfYoamkqK4D24NOLnUoHuVuhd7Q5SxZWSAO6wpDa4nrODePoJdl328pbMwCoQlUNeHINmKxh/o/oCNbgXitn4oN3kSVEg/umdgwwI94gmZUjiYwP1v7HA7dI.box";
    const BOX_2: &str = "WQyfhDDHQ1gH34uppHbj8SldRu8hD2764gQ6TAhaVp6R01EMBnJQj5ewD5F+UT5NwvV91uU8q5XCjuvcP4ihCJ0RtX8HjKyN+tDKP5gKB3UZo/eO/rP5CcPGoIG7pcLBsd3DQbZLfTnb/iqECEji9gclNcGENTS2u6aATwbQ4uQ7RzIAKKT2NfC2qk86p/gXC2owDFAazuPlQTT8DMNvO8G52gb48a75CGKsDAevrC//Bz38VFxwUiTKzRWaxCbTK9knj39u3qoCP9VLyyRqITgNwvlGLP7ndchTyBiO0TPNkb9PAOenw5WBjyWhA61hpG+VkKpkaysBVGjXYv8OpV1HGbs87TI79uT7JrNV4wEZiwqGknwmCi5B2gbd7tav8yDXsK5yQgDncHQjZotsBFX2adP7Jli9WmvV3xX5lL3kBNKV0ZiE/DZUgB2m1OXvCjNI4fuZhnpZpEQi9coO+icrirKiH/UA8TS9HI72cIbkEJVxOTnKnsgr3Qc/5HhtRS17a54ymVmBsnpP+KqqCqKLN50TInb7qoUlvQ2nw07xX3Ig9usLb8Ik8U8XMb6SLqACxlZN/qW4EJzxVetoIk84AU1yLInK6v9dzfsewRYBXW8+lYbyxVNuIIK4pKYsx2WbjuJyZHgjgbCdGf/kjqP5rDs4zwqj2lmkO70PoEUrcSi46J2hkqtcrd1yl+F3/BDwFlxAXH+x4+LhmT7g+BSgzRUbWvCyeB+HJaoao6g4K/Fs8HxnbVB1zW761OQJaQnV86ZThkvUjXh2SEBlBd+D94eUCqIJkjI7RLt+D/0gxg/D7u1Zq14UxRijZryB51An7GdXtEc2xhU+Bh/aPmKmMZ9D/ArdglSlnVUD8OIBVVw5jtooGlhxbOFHM4N5SoAO/yWPcbcuQz7t4SPij358rY574DLBGZEPCrS6KPpnrlqlnZK4f6/+9zv3hfzNTXVvJtxZL/rvmNvbgh7LpMnSqjnsXqm86a3GXeVWD83TdCnL1oPqEi/8RItTrjy01DmVhUoV6t12STP4mHb8RjR+/ks+7lowfV3HQ13n6if0g0/u+Bzv6XXOX6iePPOHA3lFv2MSPKf9JZ0uQiqajR03YkNE8YnSTYu0Io1cGPZ/lWBp2tyWtwFmGtqw/9+O165tJhrdU2EXJ4T/XP136WpLD2+vtYsx3Xr5lfeD12/g+I/6jwduqTuHpst2tqvcSWoZ4DAWcpcKJ1mUbJU3/mLAYGwWb3XuqMOgJOLoztAwd5xFzUZD1MnR/iyYoZ2weYTSOz3OKR3cJyCjxBhIGaX5xpAc61K1dXNfERBJr9TS0mL2578dd5AauE6Ksn6YlGxNJIVC3VpdAtRbVHNX1g==.box2";
    const BB_FEED: &str = "@6CAxOI3f+LUOVrbAl0IemqiS7ATpQvr9Mdw9LC4+Uv0=.bbfeed-v1";
    const CLASSIC_FEED: &str = "@d/zDvFswFbQaYJc03i47C9CgDev+/A8QQSfG5l/SEfw=.ed25519";
    const GG_FEED: &str = "@6CAxOI3f+LUOVrbAl0IemqiS7ATpQvr9Mdw9LC4+Uv0=.ggfeed-v1";
    const BB_MSG: &str = "%R8heq/tQoxEIPkWf0Kxn1nCm/CsxG2CDpUYnAvdbXY8=.bbmsg-v1";
    const CLASSIC_MSG: &str = "%R8heq/tQoxEIPkWf0Kxn1nCm/CsxG2CDpUYnAvdbXY8=.sha256";
    const GG_MSG: &str = "%R8heq/tQoxEIPkWf0Kxn1nCm/CsxG2CDpUYnAvdbXY8=.ggmsg-v1";
    const SIG: &str = "nkY4Wsn9feosxvX7bpLK7OxjdSrw6gSL8sun1n2TMLXKySYK9L5itVQnV2nQUctFsrUOa2istD2vDk1B0uAMBQ==.sig.ed25519";
}
