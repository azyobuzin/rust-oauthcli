# oauthcli
![crates.io](https://img.shields.io/crates/v/oauthcli.svg)

Yet Another OAuth 1.0 Client Library for Rust

# Features
- RFC 5849 implementation (without RSA-SHA1)
- Compatible with Twitter's (f*ckin') implementation

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

# Help me
`oauthcli` has already reached v1.0.0 although `ring` is not stable.
What shoud I do for not breaking the compatibility?
