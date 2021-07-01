/// # ssb-bfe-rs
///
/// Binary Field Encodings (BFE) for Secure Scuttlebutt (SSB).
///
/// Based on the JavaScript reference implementation: [ssb-bfe.js](https://github.com/ssb-ngi-pointer/ssb-bendy-butt/blob/master/ssb-bfe.js).
use anyhow::{anyhow, Context, Result};
use base64::decode_config_buf;
use regex::Regex;
use serde_json::Value;
use std::collections::HashMap;

#[macro_use]
extern crate lazy_static;

lazy_static! {
    // match the base64 encoded feed key between a sigil and a suffix
    static ref FEED_SUBSTRING_REGEX: Regex = Regex::new(r"@([A-Za-z0-9\\/+]{43}=).").unwrap();
    // match the base64 encoded message key between a sigil and a suffix
    static ref MSG_SUBSTRING_REGEX: Regex = Regex::new(r"%([A-Za-z0-9\\/+]{43}=).").unwrap();
    // match the base64 encoded signature key before a suffix
    static ref SIG_SUBSTRING_REGEX: Regex = Regex::new(r"([A-Za-z0-9\\/+]{43}=).").unwrap();
}

/// Encoded value for string types.
pub const STRING_TYPE: &[u8] = &[0x06, 0x00];
/// Encoded value for boolean types.
pub const BOOL_TYPE: &[u8] = &[0x06, 0x01];
/// Encoded value for null types.
pub const NULL_TYPE: &[u8] = &[0x06, 0x02];
/// Encoded value for signature types.
pub const SIGNATURE_TYPE: &[u8] = &[0x04, 0x00];
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
#[derive(Debug, PartialEq)]
pub enum ConvertedValue {
    /// Represents an encoded boolean, string, feed key, message key or signature key.
    ByteVec(Vec<u8>),
    /// Represents an object of encoded BFE values.
    HashVal(HashMap<String, ConvertedValue>),
    /// Represents an array of encoded BFE values.
    VecVal(Vec<ConvertedValue>),
}

/// Take a feed identity (key) as a string and return the type.
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

    let caps = FEED_SUBSTRING_REGEX
        .captures(feed)
        .context("No substring key was found in the given feed string")?;
    let feed_substring = caps
        .get(1)
        .context("Failed to retrieve captured substring key")?
        .as_str();

    decode_config_buf(feed_substring, base64::STANDARD, &mut encoded_feed)?;

    Ok(encoded_feed)
}

/// Take a message key as a string and return the type.
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

    let caps = MSG_SUBSTRING_REGEX
        .captures(msg)
        .context("No substring key was found in the given message string")?;
    let msg_substring = caps
        .get(1)
        .context("Failed to retrieve captured substring key")?
        .as_str();

    decode_config_buf(msg_substring, base64::STANDARD, &mut encoded_msg)?;

    Ok(encoded_msg)
}

/// Take a signature key as a string and return the encoded bytes as a vector.
pub fn encode_sig(sig: &str) -> Result<Vec<u8>> {
    let caps = SIG_SUBSTRING_REGEX
        .captures(sig)
        .context("No substring key was found in the given signature string")?;
    let sig_substring = caps
        .get(1)
        .context("Failed to retrieve captured substring key")?
        .as_str();

    let mut encoded_sig = SIGNATURE_TYPE.to_vec();
    decode_config_buf(sig_substring, base64::STANDARD, &mut encoded_sig)?;

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

/// Take a JSON value, match on the value type and call the appropriate encoder.
///
/// Returns the converted value in the form of a `Result<ConvertedValue>`.
pub fn convert(value: &Value) -> Result<ConvertedValue> {
    if value.is_array() {
        let arr = value.as_array().context("NoneError for `value.as_array`")?;
        let mut converted_arr = Vec::new();
        for item in arr {
            let converted_item = convert(item)?;
            converted_arr.push(converted_item);
        }
        Ok(ConvertedValue::VecVal(converted_arr))
    } else if value.is_null() {
        Ok(ConvertedValue::ByteVec(NULL_TYPE.to_vec()))
    } else if !value.is_array() && value.is_object() && !value.is_null() {
        let value_obj = value
            .as_object()
            .context("NoneError for `value.as_object`")?;
        let mut converted_obj = HashMap::new();
        for (k, v) in value_obj {
            let converted_value = convert(v)?;
            converted_obj.insert(k.to_string(), converted_value);
        }
        Ok(ConvertedValue::HashVal(converted_obj))
    } else if value.is_string() {
        let value_str = value.as_str().context("NoneError for `value.as_str`")?;
        if value_str.starts_with('@') {
            encode_feed(value_str).map(ConvertedValue::ByteVec)
        } else if value_str.starts_with('%') {
            encode_msg(value_str).map(ConvertedValue::ByteVec)
        } else if value_str.ends_with(".sig.ed25519") {
            encode_sig(value_str).map(ConvertedValue::ByteVec)
        } else {
            encode_string(value_str).map(ConvertedValue::ByteVec)
        }
    } else if value.is_boolean() {
        let value_bool = value.as_bool().context("NoneError for `value.as_bool`")?;
        encode_bool(value_bool).map(ConvertedValue::ByteVec)
    } else {
        // TODO: match on other types (float etc.)
        Err(anyhow!("Unknown value: no encoding performed"))
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        convert, encode_bool, encode_feed, encode_msg, encode_sig, encode_string, get_feed_type,
        get_msg_type,
    };
    use crate::{
        BB_FEED_TYPE, BB_MSG_TYPE, CLASSIC_FEED_TYPE, CLASSIC_MSG_TYPE, GG_FEED_TYPE, GG_MSG_TYPE,
    };
    use serde_json::json;

    #[test]
    fn get_feed_type_matches_bendy_butt() {
        let result = get_feed_type(&BB_FEED);
        assert!(result.is_ok());
        let result_code = result.unwrap();
        assert_eq!(result_code, BB_FEED_TYPE);
    }

    #[test]
    fn get_feed_type_matches_classic() {
        let result = get_feed_type(&CLASSIC_FEED);
        assert!(result.is_ok());
        let result_code = result.unwrap();
        assert_eq!(result_code, CLASSIC_FEED_TYPE);
    }

    #[test]
    fn get_feed_type_matches_gabby_grove() {
        let result = get_feed_type(&GG_FEED);
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
        let result = get_msg_type(&BB_MSG);
        assert!(result.is_ok());
        let result_code = result.unwrap();
        assert_eq!(result_code, BB_MSG_TYPE);
    }

    #[test]
    fn get_msg_type_matches_classic() {
        let result = get_msg_type(&CLASSIC_MSG);
        assert!(result.is_ok());
        let result_code = result.unwrap();
        assert_eq!(result_code, CLASSIC_MSG_TYPE);
    }

    #[test]
    fn get_msg_type_matches_gabby_grove() {
        let result = get_msg_type(&GG_MSG);
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
    fn encode_feed_works() {
        let result = encode_feed(&BB_FEED);
        assert!(result.is_ok());
    }

    #[test]
    fn encode_msg_works() {
        let result = encode_msg(&CLASSIC_MSG);
        assert!(result.is_ok());
    }

    #[test]
    fn encode_sig_works() {
        let result = encode_sig(&SIG);
        assert!(result.is_ok());
        let err_result = encode_sig("regex match should fail");
        assert!(err_result.is_err());
    }

    #[test]
    fn encode_string_works() {
        let result = encode_string("golden ripples in the meshwork");
        assert!(result.is_ok());
    }

    #[test]
    fn encode_bool_works() {
        let result = encode_bool(true);
        assert!(result.is_ok());
    }

    #[test]
    fn convert_bool_works() {
        let v = json!(true);
        let result = convert(&v);
        assert!(result.is_ok());
    }

    #[test]
    fn convert_array_works() {
        let v = json!(["ichneumonid", "coleopteran"]);
        let result = convert(&v);
        println!("{:?}", result);
        assert!(result.is_ok());
    }

    #[test]
    fn convert_null_works() {
        let v = json!(null);
        let result = convert(&v);
        assert!(result.is_ok());
    }

    #[test]
    fn convert_string_works() {
        let v = json!("pyrophilous fungi");
        let result = convert(&v);
        assert!(result.is_ok());
    }

    #[test]
    fn convert_value_works() {
        let v = json!({
            "feed": "@d/zDvFswFbQaYJc03i47C9CgDev+/A8QQSfG5l/SEfw=.ed25519",
            "sig": "nkY4Wsn9feosxvX7bpLK7OxjdSrw6gSL8sun1n2TMLXKySYK9L5itVQnV2nQUctFsrUOa2istD2vDk1B0uAMBQ==.sig.ed25519",
            "backups": true,
            "recurse": [null, "thing", false]
        });
        let result = convert(&v);
        assert!(result.is_ok());
    }

    const BB_FEED: &str = "@6CAxOI3f+LUOVrbAl0IemqiS7ATpQvr9Mdw9LC4+Uv0=.bbfeed-v1";
    const CLASSIC_FEED: &str = "@d/zDvFswFbQaYJc03i47C9CgDev+/A8QQSfG5l/SEfw=.ed25519";
    const GG_FEED: &str = "@6CAxOI3f+LUOVrbAl0IemqiS7ATpQvr9Mdw9LC4+Uv0=.ggfeed-v1";
    const BB_MSG: &str = "%R8heq/tQoxEIPkWf0Kxn1nCm/CsxG2CDpUYnAvdbXY8=.bbmsg-v1";
    const CLASSIC_MSG: &str = "%R8heq/tQoxEIPkWf0Kxn1nCm/CsxG2CDpUYnAvdbXY8=.sha256";
    const GG_MSG: &str = "%R8heq/tQoxEIPkWf0Kxn1nCm/CsxG2CDpUYnAvdbXY8=.ggmsg-v1";
    const SIG: &str = "nkY4Wsn9feosxvX7bpLK7OxjdSrw6gSL8sun1n2TMLXKySYK9L5itVQnV2nQUctFsrUOa2istD2vDk1B0uAMBQ==.sig.ed25519";
}
