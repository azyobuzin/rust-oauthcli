# oauthcli
Yet Another OAuth Client Library for Rust

# Features
- RFC 5849 implementation
- Very few dependencies

# How to Use
```rust
extern crate oauthcli;
extern crate url;

let header =
  oauthcli::authorization_header(
    "POST",
    url::Url::parse("https://example").unwrap(),
    None, // Realm
    "Consumer Key",
    "Consumer Secret",
    Some("OAuth Token"),
    Some("OAuth Token Secret"),
    oauthcli::SignatureMethod::HmacSha1, // or Plaintext
    oauthcli::timestamp(),
    oauthcli::nonce(),
    None, // oauth_callback
    None, // oauth_verifier
    vec![("status".to_string(), "hello".to_string())].iter()
  );
```
