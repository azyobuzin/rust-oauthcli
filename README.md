# oauthcli
![crates.io](https://img.shields.io/crates/v/oauthcli.svg)

Yet Another OAuth 1.0 Client Library for Rust

# Features
- RFC 5849 implementation
- Very few dependencies

# How to Use
```rust
extern crate oauthcli;
extern crate url;

let header =
  oauthcli::OAuthAuthorizationHeaderBuilder::new(
    "POST",
    url::Url::parse("https://example").unwrap(),
    "Consumer Key",
    "Consumer Secret",
    oauthcli::SignatureMethod::HmacSha1 // or Plaintext
  )
  .token("OAuth Token", "OAuth Token Secret")
  .request_parameters(vec![("status", "hello")].into_iter())
  .finish();

assert_eq!(header.to_string(), "OAuth ......")
```