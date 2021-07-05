//! # ssb-bfe-rs
//!
//! Binary Field Encodings (BFE) for Secure Scuttlebutt (SSB).
//!
//! Based on the JavaScript reference implementation: [ssb-bfe.js](https://github.com/ssb-ngi-pointer/ssb-bendy-butt/blob/master/ssb-bfe.js).
//!
//! While `encode()` and `decode()` are the two primary functions exposed by this crate, the
//! various helper functions and values are also exported for public use.
//!
//! ## Encode
//!
//! The encoder expects JSON input in the form of a [`serde_json::Value
//! enum`](https://docs.serde.rs/serde_json/value/enum.Value.html). The encoded value is returned
//! as an `EncodedValue` (a custom `enum` provided by this library).
//!
//! ## Decode
//!
//! The decoder expects input in the form of an `EncodedValue` (a custom `enum` provided by this
//! library). The decoded value is returned as JSON in the form of a [`serde_json::Value enum`](https://docs.serde.rs/serde_json/value/enum.Value.html).
//!
//!`Deserialize` and `Serialize` traits have been derived for `EncodedValue`,
//!meaning that encoded JSON objects can be parsed into the `EncodedValue`
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

/// Encoded value for string types.
pub const STRING_TYPE: &[u8] = &[0x06, 0x00];
/// Encoded value for boolean types.
pub const BOOL_TYPE: &[u8] = &[0x06, 0x01];
/// Encoded value for null types.
pub const NULL_TYPE: &[u8] = &[0x06, 0x02];
/// Encoded value for signature types.
pub const SIGNATURE_TYPE: &[u8] = &[0x04, 0x00];
/// Encoded value for feed type.
pub const FEED_TYPE: &[u8] = &[0x00];
/// Encoded value for message type.
pub const MSG_TYPE: &[u8] = &[0x01];
/// Encoded value for classic (legacy) feed types.
pub const CLASSIC_FEED_TYPE: &[u8] = &[0x00, 0x00];
/// Encoded value for Gabby Grove (GG) feed types.
pub const GG_FEED_TYPE: &[u8] = &[0x00, 0x01];
/// Encoded value for Bendy Butt (BB) feed types.
pub const BB_FEED_TYPE: &[u8] = &[0x00, 0x03];
/// Encoded value for classic (legacy) message types.
pub const CLASSIC_MSG_TYPE: &[u8] = &[0x01, 0x00];
/// Encoded value for Gabby Grove (GG) message types.
pub const GG_MSG_TYPE: &[u8] = &[0x01, 0x01];
/// Encoded value for Bendy Butt (BB) message types.
pub const BB_MSG_TYPE: &[u8] = &[0x01, 0x04];

/// Represents any valid encoded BFE value.
#[derive(Debug, PartialEq, Deserialize, Serialize)]
pub enum EncodedValue {
    /// Represents an encoded boolean, string, feed key, message key or signature key.
    Buffer(Vec<u8>),
    /// Represents an object of encoded BFE values.
    #[serde(with = "indexmap::serde_seq")]
    Object(IndexMap<String, EncodedValue>),
    /// Represents an array of encoded BFE values.
    Array(Vec<EncodedValue>),
}

/// Take a feed identity (key) as a string and return the encoded bytes representing the feed type.
pub fn get_feed_type(feed: &str) -> Result<Vec<u8>> {
    let feed_type;
    if feed.ends_with(".ed25519") {
        feed_type = CLASSIC_FEED_TYPE
    } else if feed.ends_with(".bbfeed-v1") {
        feed_type = BB_FEED_TYPE
    } else if feed.ends_with(".ggfeed-v1") {
        feed_type = GG_FEED_TYPE
    } else {
        return Err(anyhow!("The feed type is of an unknown format"));
    };

    Ok(feed_type.to_vec())
}

/// Take a feed identity (key) as a string and return the encoded bytes as a vector.
pub fn encode_feed(feed: &str) -> Result<Vec<u8>> {
    let mut encoded_feed = get_feed_type(feed)?;
    let dot_index = feed
        .rfind('.')
        .context("Invalid feed string: no dot index was found")?;
    // decode feed substring from base64 str to bytes and append to encoded_feed bytes
    base64::decode_config_buf(&feed[1..dot_index], base64::STANDARD, &mut encoded_feed)?;

    Ok(encoded_feed)
}

/// Take a message key as a string and return the encoded bytes representing the message type.
pub fn get_msg_type(msg: &str) -> Result<Vec<u8>> {
    let msg_type;
    if msg.ends_with(".sha256") {
        msg_type = CLASSIC_MSG_TYPE
    } else if msg.ends_with(".bbmsg-v1") {
        msg_type = BB_MSG_TYPE
    } else if msg.ends_with(".ggmsg-v1") {
        msg_type = GG_MSG_TYPE
    } else {
        return Err(anyhow!("The message type is unknown"));
    };

    Ok(msg_type.to_vec())
}

/// Take a message key as a string and return the encoded bytes as a vector.
pub fn encode_msg(msg: &str) -> Result<Vec<u8>> {
    let mut encoded_msg = get_msg_type(msg)?;
    let dot_index = msg
        .rfind('.')
        .context("Invalid message string: no dot index was found")?;
    // decode msg substring from base64 str to bytes and append to encoded_msg bytes
    base64::decode_config_buf(&msg[1..dot_index], base64::STANDARD, &mut encoded_msg)?;

    Ok(encoded_msg)
}

/// Take a signature key as a string and return the encoded bytes as a vector.
pub fn encode_sig(sig: &str) -> Result<Vec<u8>> {
    let mut encoded_sig = SIGNATURE_TYPE.to_vec();
    let sig_substring = sig
        .strip_suffix(".sig.ed25519")
        .context("Signature does not have a valid `.sig.ed25519` suffix")?;
    // decode sig substring from base64 str to bytes and append to encoded_sig bytes
    base64::decode_config_buf(sig_substring, base64::STANDARD, &mut encoded_sig)?;

    Ok(encoded_sig)
}

/// Take a string value and return the encoded bytes as a vector.
pub fn encode_string(string: &str) -> Result<Vec<u8>> {
    let encoded_string = [STRING_TYPE, string.as_bytes()].concat();

    Ok(encoded_string)
}

/// Take a boolean value as a string and return the encoded bytes as a vector.
pub fn encode_bool(boolean: bool) -> Result<Vec<u8>> {
    let bool_vec = match boolean {
        true => [BOOL_TYPE, &[0x01]].concat(),
        false => [BOOL_TYPE, &[0x00]].concat(),
    };

    Ok(bool_vec.to_vec())
}

/// Take a JSON value, match on the value type(s) and call the appropriate encoder(s).
///
/// Returns the encoded value in the form of a `Result<EncodedValue>`.
pub fn encode(value: &Value) -> Result<EncodedValue> {
    if value.is_array() {
        let value_arr = value.as_array().context("NoneError for `value.as_array`")?;
        let mut encoded_arr = Vec::new();
        for item in value_arr {
            let encoded_item = encode(item)?;
            encoded_arr.push(encoded_item);
        }
        Ok(EncodedValue::Array(encoded_arr))
    } else if value.is_null() {
        Ok(EncodedValue::Buffer(NULL_TYPE.to_vec()))
    } else if !value.is_array() && value.is_object() && !value.is_null() {
        let value_obj = value
            .as_object()
            .context("NoneError for `value.as_object`")?;
        let mut encoded_obj = IndexMap::new();
        for (k, v) in value_obj {
            let encoded_value = encode(v)?;
            encoded_obj.insert(k.to_string(), encoded_value);
        }
        Ok(EncodedValue::Object(encoded_obj))
    } else if value.is_string() {
        let value_str = value.as_str().context("NoneError for `value.as_str`")?;
        let encoded_str;
        if value_str.starts_with('@') {
            encoded_str = encode_feed(value_str)?
        } else if value_str.starts_with('%') {
            encoded_str = encode_msg(value_str)?
        } else if value_str.ends_with(".sig.ed25519") {
            encoded_str = encode_sig(value_str)?
        } else {
            encoded_str = encode_string(value_str)?
        }
        Ok(EncodedValue::Buffer(encoded_str))
    } else if value.is_boolean() {
        let value_bool = value.as_bool().context("NoneError for `value.as_bool`")?;
        let encoded_bool = encode_bool(value_bool)?;
        Ok(EncodedValue::Buffer(encoded_bool))
    } else {
        // TODO: match on other types (float etc.)
        Err(anyhow!("Unknown value: no encoding performed"))
    }
}

/// Take a feed identity (key) as an encoded byte vector and return a string representing the feed
/// type.
pub fn decode_feed(feed: Vec<u8>) -> Result<String> {
    let feed_extension;
    if &feed[..2] == CLASSIC_FEED_TYPE {
        feed_extension = ".ed25519"
    } else if &feed[..2] == BB_FEED_TYPE {
        feed_extension = ".bbfeed-v1"
    } else if &feed[..2] == GG_FEED_TYPE {
        feed_extension = ".ggfeed-v1"
    } else {
        return Err(anyhow!("The feed is of an unknown format"));
    }

    // encode the last two bytes of the feed identity as base64
    let b64_type = base64::encode(&feed[2..]);
    let decoded_feed = format!("@{}{}", b64_type, feed_extension.to_string());

    Ok(decoded_feed)
}

/// Take a message key as an encoded byte vector and return a string representing the message type.
pub fn decode_msg(msg: Vec<u8>) -> Result<Option<String>> {
    if msg.len() == 2 {
        return Ok(None);
    }
    let msg_extension;
    if &msg[..2] == CLASSIC_MSG_TYPE {
        msg_extension = ".sha256"
    } else if &msg[..2] == BB_MSG_TYPE {
        msg_extension = ".bbmsg-v1"
    } else if &msg[..2] == GG_MSG_TYPE {
        msg_extension = ".ggmsg-v1"
    } else {
        return Err(anyhow!("The message is of an unknown format"));
    }

    let b64_type = base64::encode(&msg[2..]);
    let decoded_feed = format!("%{}{}", b64_type, msg_extension.to_string());

    Ok(Some(decoded_feed))
}

/// Take a signature key as an encoded byte vector and return a string.
pub fn decode_sig(sig: Vec<u8>) -> Result<String> {
    let b64_type = base64::encode(&sig[2..]);
    let decoded_sig = format!("{}.sig.ed25519", b64_type);

    Ok(decoded_sig)
}

/// Take a string as an encoded byte vector and return a string.
pub fn decode_string(string: Vec<u8>) -> Result<String> {
    let decoded_string = str::from_utf8(&string[2..])
        .context("The string bytes are not valid UTF-8")?
        .to_owned();

    Ok(decoded_string)
}

/// Take a boolean key as an encoded byte vector and return a boolean value.
pub fn decode_bool(boolean: Vec<u8>) -> bool {
    boolean[2..] == [0x01]
}

/// Take a BFE encoded value, match on the value type(s) and call the appropriate decoder(s).
///
/// Returns the decoded value in the form of a `Result<Value>`.
pub fn decode(value: &EncodedValue) -> Result<Value> {
    match value {
        EncodedValue::Array(arr) => {
            let mut decoded_arr = Vec::new();
            for item in arr {
                let decoded_item = decode(item)?;
                decoded_arr.push(decoded_item);
            }
            Ok(json!(decoded_arr))
        }
        EncodedValue::Buffer(buf) => {
            let mut decoded_buf = None;
            if buf.len() < 2 {
                return Err(anyhow!("Buffer length < 2"));
            } else if &buf[..2] == STRING_TYPE {
                decoded_buf = Some(decode_string(buf.to_vec())?)
            } else if &buf[..2] == BOOL_TYPE {
                return Ok(json!(decode_bool(buf.to_vec())));
            } else if &buf[..2] == NULL_TYPE {
                decoded_buf = None
            } else if &buf[..1] == FEED_TYPE {
                decoded_buf = Some(decode_feed(buf.to_vec())?)
            } else if &buf[..1] == MSG_TYPE {
                // ignore the None return type (msg.len() == 2)
                if let Some(val) = decode_msg(buf.to_vec())? {
                    decoded_buf = Some(val)
                }
            } else if &buf[..2] == SIGNATURE_TYPE {
                decoded_buf = Some(decode_sig(buf.to_vec())?)
            } else {
                let buffer_str =
                    str::from_utf8(buf).context("The string bytes are not valid UTF-8")?;
                decoded_buf = Some(base64::encode(buffer_str))
            }
            Ok(json!(decoded_buf))
        }
        EncodedValue::Object(obj) => {
            let mut decoded_obj = IndexMap::new();
            for (k, v) in obj {
                let decoded_value = decode(v)?;
                decoded_obj.insert(k.to_string(), decoded_value);
            }
            Ok(json!(decoded_obj))
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::EncodedValue;
    use crate::{
        decode, decode_bool, decode_feed, decode_msg, decode_sig, decode_string, encode,
        encode_bool, encode_feed, encode_msg, encode_sig, encode_string, get_feed_type,
        get_msg_type,
    };
    use crate::{
        BB_FEED_TYPE, BB_MSG_TYPE, CLASSIC_FEED_TYPE, CLASSIC_MSG_TYPE, GG_FEED_TYPE, GG_MSG_TYPE,
    };
    use serde_json::json;

    #[test]
    fn get_feed_type_matches_bendy_butt() {
        let result = get_feed_type(BB_FEED);
        assert!(result.is_ok());
        let result_code = result.unwrap();
        assert_eq!(result_code, BB_FEED_TYPE);
    }

    #[test]
    fn get_feed_type_matches_classic() {
        let result = get_feed_type(CLASSIC_FEED);
        assert!(result.is_ok());
        let result_code = result.unwrap();
        assert_eq!(result_code, CLASSIC_FEED_TYPE);
    }

    #[test]
    fn get_feed_type_matches_gabby_grove() {
        let result = get_feed_type(GG_FEED);
        assert!(result.is_ok());
        let result_code = result.unwrap();
        assert_eq!(result_code, GG_FEED_TYPE);
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
        assert_eq!(result_code, BB_MSG_TYPE);
    }

    #[test]
    fn get_msg_type_matches_classic() {
        let result = get_msg_type(CLASSIC_MSG);
        assert!(result.is_ok());
        let result_code = result.unwrap();
        assert_eq!(result_code, CLASSIC_MSG_TYPE);
    }

    #[test]
    fn get_msg_type_matches_gabby_grove() {
        let result = get_msg_type(GG_MSG);
        assert!(result.is_ok());
        let result_code = result.unwrap();
        assert_eq!(result_code, GG_MSG_TYPE);
    }

    #[test]
    fn get_msg_type_matches_unknown() {
        let result = get_msg_type("%what.is_this-v1");
        assert!(result.is_err());
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
    fn encode_value_bool_works() {
        let v = json!(true);
        let result = encode(&v);
        assert!(result.is_ok());
    }

    #[test]
    fn encode_value_array_works() {
        let v = json!(["ichneumonid", "coleopteran"]);
        let result = encode(&v);
        assert!(result.is_ok());
    }

    #[test]
    fn encode_value_null_works() {
        let v = json!(null);
        let encoded = encode(&v);
        assert!(encoded.is_ok());
        let encoded_value = encoded.unwrap();
        assert_eq!(EncodedValue::Buffer([6, 2].to_vec()), encoded_value);
    }

    #[test]
    fn encode_value_string_works() {
        let v = json!("pyrophilous fungi");
        let result = encode(&v);
        assert!(result.is_ok());
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

    const BB_FEED: &str = "@6CAxOI3f+LUOVrbAl0IemqiS7ATpQvr9Mdw9LC4+Uv0=.bbfeed-v1";
    const CLASSIC_FEED: &str = "@d/zDvFswFbQaYJc03i47C9CgDev+/A8QQSfG5l/SEfw=.ed25519";
    const GG_FEED: &str = "@6CAxOI3f+LUOVrbAl0IemqiS7ATpQvr9Mdw9LC4+Uv0=.ggfeed-v1";
    const BB_MSG: &str = "%R8heq/tQoxEIPkWf0Kxn1nCm/CsxG2CDpUYnAvdbXY8=.bbmsg-v1";
    const CLASSIC_MSG: &str = "%R8heq/tQoxEIPkWf0Kxn1nCm/CsxG2CDpUYnAvdbXY8=.sha256";
    const GG_MSG: &str = "%R8heq/tQoxEIPkWf0Kxn1nCm/CsxG2CDpUYnAvdbXY8=.ggmsg-v1";
    const SIG: &str = "nkY4Wsn9feosxvX7bpLK7OxjdSrw6gSL8sun1n2TMLXKySYK9L5itVQnV2nQUctFsrUOa2istD2vDk1B0uAMBQ==.sig.ed25519";
}
