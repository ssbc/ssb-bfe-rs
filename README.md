<!--
SPDX-FileCopyrightText: 2021 Andrew 'glyph' Reid

SPDX-License-Identifier: CC0-1.0
-->

# ssb-bfe-rs

Binary Field Encodings (BFE) for Secure Scuttlebutt (SSB).

[![ssb-bfe-rs crate](https://img.shields.io/crates/v/ssb-bfe-rs)](https://crates.io/crates/ssb-bfe-rs)

Based on the JavaScript reference implementation: [ssb-bfe](https://github.com/ssb-ngi-pointer/ssb-bfe) (written according to the [specification](https://github.com/ssb-ngi-pointer/ssb-binary-field-encodings-spec)).

While `encode()` and `decode()` are the two primary functions exposed by this crate, the various helper functions and values are also exported for public use.

## Encode

The encoder expects JSON input in the form of a [`serde_json::Value enum`](https://docs.serde.rs/serde_json/value/enum.Value.html). The encoded value is returned
as an `BfeValue` (a custom `enum` provided by this library).

## Decode

The decoder expects input in the form of an `BfeValue` (a custom `enum` provided by this library). The decoded value is returned as JSON in the form of a [`serde_json::Value enum`](https://docs.serde.rs/serde_json/value/enum.Value.html).

`Deserialize` and `Serialize` traits have been derived for `BfeValue`, meaning that encoded JSON objects can be parsed into the `BfeValue` type if required (for example, if the value is received as a byte slice of serialized JSON data). See the `serde` documentation on [Parsing JSON as strongly typed data structures](https://docs.serde.rs/serde_json/index.html#parsing-json-as-strongly-typed-data-structures) for an example and further explanation.

## Example

```rust
use ssb_bfe_rs;
use serde_json::json;

let value = json!({
    "author": "@6CAxOI3f+LUOVrbAl0IemqiS7ATpQvr9Mdw9LC4+Uv0=.bbfeed-v1",
    "previous": "%R8heq/tQoxEIPkWf0Kxn1nCm/CsxG2CDpUYnAvdbXY8=.bbmsg-v1"
});

let encoded = ssb_bfe_rs::encode(&value)?;
println!("{:X?}", encoded);

// Object({"author": Buffer([0, 3, E8, 20, 31, 38, 8D, DF, F8, B5, E, 56, B6, C0, 97, 42, 1E, 9A, A8, 92, EC, 4, E9, 42, FA, FD, 31, DC, 3D, 2C, 2E, 3E, 52, FD]), "previous": Buffer([1, 4, 47, C8, 5E, AB, FB, 50, A3, 11, 8, 3E, 45, 9F, D0, AC, 67, D6, 70, A6, FC, 2B, 31, 1B, 60, 83, A5, 46, 27, 2, F7, 5B, 5D, 8F])})

let decoded = ssb_bfe_rs::decode(&encoded_value)?;
println!("{:?}", decoded);

// Object({"author": String("@6CAxOI3f+LUOVrbAl0IemqiS7ATpQvr9Mdw9LC4+Uv0=.bbfeed-v1"), "previous": String("%R8heq/tQoxEIPkWf0Kxn1nCm/CsxG2CDpUYnAvdbXY8=.bbmsg-v1")})
```

## Documentation

Use `cargo doc` to generate and serve the Rust documentation for this library:

```bash
git clone git@github.com:ssb-ngi-pointer/ssb-bfe-rs.git
cd ssb-bfe-rs
cargo doc --no-deps --open 
```

## License

LGPL-3.0.
