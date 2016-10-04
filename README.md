# oauthcli
![crates.io](https://img.shields.io/crates/v/oauthcli.svg)

Yet Another OAuth 1.0 Client Library for Rust

[Documentation](http://azyobuzin.github.io/rust-oauthcli/oauthcli/)

# Features
- RFC 5849 implementation (without RSA-SHA1)
- Compatible with Twitter's (f*ckin') implementation
- Integration with `hyper::header::Authorization`

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
