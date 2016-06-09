# oauthcli
Yet Another OAuth 1.0 Client Library for Rust

# Features
- RFC 5849 implementation
- Very few dependencies

# How to Use
```rust
extern crate oauthcli;

let header =
  oauthcli::authorization_header(
    "POST",
    oauthcli::url::Url::parse("https://example").unwrap(),
    None, // Realm
    "Consumer Key",
    "Consumer Secret",
    Some("OAuth Token"),
    Some("OAuth Token Secret"),
    oauthcli::SignatureMethod::HmacSha1, // or Plaintext
    &oauthcli::timestamp()[],
    &oauthcli::nonce()[],
    None, // oauth_callback
    None, // oauth_verifier
    vec![("status".to_string(), "hello".to_string())].into_iter()
  );

// header = "OAuth ......"
```
