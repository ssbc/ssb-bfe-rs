/// # Binary Field Encoding (BFE) Specification Data
///
/// This represents all the constant values used for BFE, defined in the [specification](https://github.com/ssb-ngi-pointer/ssb-bfe-spec/blob/master/bfe.json).
///
/// _Note_: not all of these type-format variants are currently supported in ssb-bfe-rs.
use phf::{phf_ordered_map, OrderedMap};

/// A tuple struct defining all possible BFE specification data points.
pub struct BfeSpecData<'a>(
    pub &'a [u8],        // type_format_code
    pub Option<usize>,   // data_length
    pub Option<usize>,   // key_length
    pub Option<usize>,   // signature_length
    pub Option<&'a str>, // sigil
    pub Option<&'a str>, // suffix
);

/// Encoded value for boolean true value.
pub const BOOL_TRUE: &[u8] = &[0x01];
/// Encoded value for boolean false value.
pub const BOOL_FALSE: &[u8] = &[0x00];

/// An ordered map of all BFE types. The key for each entry is the name of a type and the value is
/// a tuple containing the code for the type and an ordered map of the associated formats.
///
/// **Example usage:**
///
/// Tuple indexing or destructuring can be used to access values.
///
/// ```rust
/// // get the type code for "feed"
/// let feed_type_code = TYPES["feed"].0;
///
/// // get the formats for "message"
/// let mgs_formats = TYPES["message"].1;
///
/// // get the type code and formats for "blob"
/// let (code, formats) = TYPES["blob"];
/// ```
pub const TYPES: OrderedMap<&str, (&[u8], OrderedMap<&str, BfeSpecData>)> = phf_ordered_map! {
    // "type_name" =>   (type_code, type_formats)
    "feed" =>           (&[0x00], FEED_FORMATS),
    "message" =>        (&[0x01], MSG_FORMATS),
    "blob" =>           (&[0x02], BLOB_FORMATS),
    "encryption-key" => (&[0x03], ENCRYPTION_KEY_FORMATS),
    "signature" =>      (&[0x04], SIGNATURE_FORMATS),
    "encrypted" =>      (&[0x05], ENCRYPTED_FORMATS),
    "generic" =>        (&[0x06], GENERIC_FORMATS),
    "identity" =>       (&[0x07], IDENTITY_FORMATS),
};

/// An ordered map of all BFE formats associated with the "feed" type. The key for each entry is the name of a format and the value is
/// a `BfeSpecData` tuple containing the code for the type-format, the data length, the key length, the signature length, the sigil and the suffix.
///
/// _Note_: most of the fields in the tuple are `None` values. The `BfeSpecData` has been designed
/// to be generic over all possible type formats. In the case of the "feed" type, only the
/// type-format code, data length, sigil and suffix contain relevant values.
///
/// **Example usage:**
///
/// Tuple indexing or destructuring can be used to access values.
///
/// ```rust
/// // get the bfe spec data for the "gabbygrove-v1" "feed" format
/// let classic_feed_data = FEED_FORMATS["gabbygrove-v1"];
///
/// // get the type-format code for "classic" "feed" format
/// let classic_feed_tf = FEED_FORMATS["classic"].0;
///
/// // get the type-format code, data length, sigil and suffix for the "classic" "feed" format (`_` means "ignore this position in the tuple")
/// let BfeSpecData(code, data_len, _, _, sigil, suffix) = FEED_FORMATS["classic"];
/// ```
pub const FEED_FORMATS: OrderedMap<&str, BfeSpecData> = phf_ordered_map! {
    // "format_name" => BfeSpecData(type_format_code, data_length, key_length, signature_length, sigil, suffix)
    "classic" =>        BfeSpecData(&[0x00, 0x00], Some(32), None, None, Some("@"), Some(".ed25519")),
    "gabbygrove-v1" =>  BfeSpecData(&[0x00, 0x01], Some(32), None, None, None, None),
    "bamboo" =>         BfeSpecData(&[0x00, 0x02], Some(32), None, None, None, None),
    "bendybutt-v1" =>   BfeSpecData(&[0x00, 0x03], Some(32), None, None, None, None),
};

/// An ordered map of all BFE formats associated with the "message" type. The key for each entry is the name of a format and the value is
/// a `BfeSpecData` tuple containing the code for the type-format, the data length, the key length, the signature length, the sigil and the suffix.
pub const MSG_FORMATS: OrderedMap<&str, BfeSpecData> = phf_ordered_map! {
    "classic" =>        BfeSpecData(&[0x01, 0x00], Some(32), None, None, Some("%"), Some(".sha256")),
    "gabbygrove-v1" =>  BfeSpecData(&[0x01, 0x01], Some(32), None, None, None, None),
    "cloaked" =>        BfeSpecData(&[0x01, 0x02], Some(32), None, None, Some("%"), Some(".cloaked")),
    "bamboo" =>         BfeSpecData(&[0x01, 0x03], Some(64), None, None, None, None),
    "bendybutt-v1" =>   BfeSpecData(&[0x01, 0x04], Some(32), None, None, None, None),
};

/// An ordered map of all BFE formats associated with the "blob" type. The key for each entry is the name of a format and the value is
/// a `BfeSpecData` tuple containing the code for the type-format, the data length, the key length, the signature length, the sigil and the suffix.
pub const BLOB_FORMATS: OrderedMap<&str, BfeSpecData> = phf_ordered_map! {
    "classic" =>        BfeSpecData(&[0x02, 0x00], Some(32), None, None, Some("&"), Some(".sha256"))
};

/// An ordered map of all BFE formats associated with the "encryption-key" type. The key for each entry is the name of a format and the value is
/// a `BfeSpecData` tuple containing the code for the type-format, the data length, the key length, the signature length, the sigil and the suffix.
pub const ENCRYPTION_KEY_FORMATS: OrderedMap<&str, BfeSpecData> = phf_ordered_map! {
    "box2-dm-dh" =>     BfeSpecData(&[0x03, 0x00], Some(32), None, None, Some("&"), Some(".sha256")),
    "box2-pobox-dh" =>  BfeSpecData(&[0x03, 0x01], Some(32), None, None, Some("&"), Some(".sha256")),
};

/// An ordered map of all BFE formats associated with the "signature" type. The key for each entry is the name of a format and the value is
/// a `BfeSpecData` tuple containing the code for the type-format, the data length, the key length, the signature length, the sigil and the suffix.
pub const SIGNATURE_FORMATS: OrderedMap<&str, BfeSpecData> = phf_ordered_map! {
    "msg-ed25519" =>    BfeSpecData(&[0x04, 0x00], Some(64), None, Some(64), None, Some(".sig.ed25519"))
};

/// An ordered map of all BFE formats associated with the "encrypted" type. The key for each entry is the name of a format and the value is
/// a `BfeSpecData` tuple containing the code for the type-format, the data length, the key length, the signature length, the sigil and the suffix.
pub const ENCRYPTED_FORMATS: OrderedMap<&str, BfeSpecData> = phf_ordered_map! {
    "box1" =>           BfeSpecData(&[0x05, 0x00], None, None, None, None, Some(".box")),
    "box2" =>           BfeSpecData(&[0x05, 0x01], None, None, None, None, Some(".box2")),
};

/// An ordered map of all BFE formats associated with the "generic" type. The key for each entry is the name of a format and the value is
/// a `BfeSpecData` tuple containing the code for the type-format, the data length, the key length, the signature length, the sigil and the suffix.
pub const GENERIC_FORMATS: OrderedMap<&str, BfeSpecData> = phf_ordered_map! {
    "string-UTF8" =>    BfeSpecData(&[0x06, 0x00], None, None, None, None, None),
    "boolean" =>        BfeSpecData(&[0x06, 0x01], None, None, None, None, None),
    "nil" =>            BfeSpecData(&[0x06, 0x02], None, None, None, None, None),
    "any-bytes" =>      BfeSpecData(&[0x06, 0x03], None, None, None, None, None),
};

/// An ordered map of all BFE formats associated with the "identity" type. The key for each entry is the name of a format and the value is
/// a `BfeSpecData` tuple containing the code for the type-format, the data length, the key length, the signature length, the sigil and the suffix.
pub const IDENTITY_FORMATS: OrderedMap<&str, BfeSpecData> = phf_ordered_map! {
    "po-box" =>         BfeSpecData(&[0x07, 0x00], Some(32), None, None, None, None)
};
