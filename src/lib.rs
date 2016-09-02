//! Yet Another OAuth 1.0 Client Library for Rust
// TODO: Write examples.

extern crate rand;
extern crate rustc_serialize;
extern crate time;
extern crate url;

pub mod security;
#[cfg(test)] mod tests;

use security::*;
use std::ascii::AsciiExt;
use std::borrow::Cow;
use std::fmt::{self, Write};
use std::iter;
use rand::Rng;
use rustc_serialize::base64::{self, ToBase64};
use url::{Url, percent_encoding};

/// Available `oauth_signature_method` types.
#[derive(Copy, Debug, PartialEq, Eq, Clone, Hash)]
pub enum SignatureMethod {
    /// HMAC-SHA1
    HmacSha1,
    /// PLAINTEXT
    Plaintext
}

impl SignatureMethod {
    fn to_str(&self) -> &'static str {
        match *self {
            SignatureMethod::HmacSha1 => "HMAC-SHA1",
            SignatureMethod::Plaintext => "PLAINTEXT"
        }
    }
}

impl fmt::Display for SignatureMethod {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(self.to_str())
    }
}

/// [RFC 5849 section 3.6](http://tools.ietf.org/html/rfc5849#section-3.6).
#[derive(Copy, Clone)]
#[allow(non_camel_case_types)]
pub struct OAUTH_ENCODE_SET;

impl percent_encoding::EncodeSet for OAUTH_ENCODE_SET {
    fn contains(&self, byte: u8) -> bool {
        !((byte >= 0x30 && byte <= 0x39)
        || (byte >= 0x41 && byte <= 0x5A)
        || (byte >= 0x61 && byte <= 0x7A)
        || byte == 0x2D || byte == 0x2E
        || byte == 0x5F || byte == 0x7E)
    }
}

fn percent_encode(input: &str) -> percent_encoding::PercentEncode<OAUTH_ENCODE_SET> {
    percent_encoding::utf8_percent_encode(input, OAUTH_ENCODE_SET)
}

/// `Authorization` header for OAuth.
///
/// # Example
/// ```
/// # use oauthcli::OAuthAuthorizationHeader;
/// let header = OAuthAuthorizationHeader { auth_param: "oauth_consumer_key=...".to_string() };
/// assert_eq!(header.to_string(), "OAuth oauth_consumer_key=...");
/// ```
#[derive(Debug, Clone)]
pub struct OAuthAuthorizationHeader {
    /// `auth-param` in RFC 7235
    pub auth_param: String
}

impl fmt::Display for OAuthAuthorizationHeader {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "OAuth {}", self.auth_param)
    }
}

fn base_string_url(url: &Url) -> String {
    let scheme = url.scheme();

    let mut result = String::with_capacity(url.as_str().len());

    write!(&mut result, "{}://{}", scheme, url.host_str().expect("The host is None")).unwrap();

    if let Some(p) = url.port() {
        match (scheme, p) {
            ("http", 80) | ("https", 443) => (),
            ("http", p) | ("https", p) => write!(&mut result, ":{}", p).unwrap(),
            _ => panic!("The scheme is not \"http\" or \"https\"")
        }
    }

    result.push_str(url.path());
    result
}

fn normalize_parameters<'a, P>(params: P) -> String
    where P: Iterator<Item = (Cow<'a, str>, Cow<'a, str>)>
{
    let mut mutparams: Vec<_> = params
        .map(|(k, v)| (percent_encode(&k).to_string(), percent_encode(&v).to_string()))
        .collect();

    let mut result = String::new();

    if mutparams.len() > 0 {
        mutparams.sort();

        let mut first = true;
        for (key, val) in mutparams.into_iter() {
            if first { first = false; }
            else { result.push('&'); }

            write!(&mut result, "{}={}", key, val).unwrap();
        }
    }

    result
}

fn gen_timestamp() -> u64 {
    let x = time::now_utc().to_timespec().sec;
    assert!(x > 0);
    return x as u64;
}

/// Generate a string for `oauth_timestamp`.
#[deprecated(since = "1.0.0")]
pub fn timestamp() -> String {
    gen_timestamp().to_string()
}

/// Generate a string for `oauth_nonce`.
pub fn nonce() -> String {
    rand::thread_rng().gen_ascii_chars()
        .take(42).collect()
}

pub struct OAuthAuthorizationHeaderBuilder<'a> {
    method: Cow<'a, str>,
    url: &'a Url,
    parameters: Vec<(Cow<'a, str>, Cow<'a, str>)>,
    consumer_key: Cow<'a, str>,
    consumer_secret: Cow<'a, str>,
    signature_method: SignatureMethod,
    realm: Option<Cow<'a, str>>,
    token: Option<Cow<'a, str>>,
    token_secret: Option<Cow<'a, str>>,
    timestamp: Option<u64>,
    nonce: Option<Cow<'a, str>>,
    callback: Option<Cow<'a, str>>,
    verifier: Option<Cow<'a, str>>,
    include_version: bool
}

impl<'a> OAuthAuthorizationHeaderBuilder<'a> {
    pub fn new<M, C, S>(method: M, url: &'a Url, consumer_key: C, consumer_secret: S, signature_method: SignatureMethod) -> Self
        where M: Into<Cow<'a, str>>, C: Into<Cow<'a, str>>, S: Into<Cow<'a, str>>
    {
        OAuthAuthorizationHeaderBuilder {
            method: method.into(),
            url: url,
            parameters: Vec::new(),
            consumer_key: consumer_key.into(),
            consumer_secret: consumer_secret.into(),
            signature_method: signature_method,
            realm: None,
            token: None,
            token_secret: None,
            timestamp: None,
            nonce: None,
            callback: None,
            verifier: None,
            include_version: true
        }
    }

    pub fn request_parameters<K, V, P>(&mut self, parameters: P) -> &mut Self
        where K: Into<Cow<'a, str>>, V: Into<Cow<'a, str>>, P: IntoIterator<Item=(K, V)>
    {
        self.parameters.extend(parameters.into_iter().map(|(k, v)| (k.into(), v.into())));
        self
    }

    pub fn realm<T: Into<Cow<'a, str>>>(&mut self, realm: T) -> &mut Self {
        self.realm = Some(realm.into());
        self
    }

    pub fn token<T, S>(&mut self, token: T, secret: S) -> &mut Self
        where T: Into<Cow<'a, str>>, S: Into<Cow<'a, str>>
    {
        self.token = Some(token.into());
        self.token_secret = Some(secret.into());
        self
    }

    /// Sets a custom timestamp.
    /// If you don't call `timestamp()`, it will use the current time.
    pub fn timestamp(&mut self, timestamp: u64) -> &mut Self {
        self.timestamp = Some(timestamp);
        self
    }

    /// Sets a custom nonce.
    /// If you don't call `nonce()`, it will use a random string.
    pub fn nonce<T: Into<Cow<'a, str>>>(&mut self, nonce: T) -> &mut Self {
        self.nonce = Some(nonce.into());
        self
    }

    pub fn callback<T: Into<Cow<'a, str>>>(&mut self, callback: T) -> &mut Self {
        self.callback = Some(callback.into());
        self
    }

    pub fn verifier<T: Into<Cow<'a, str>>>(&mut self, verifier: T) -> &mut Self {
        self.verifier = Some(verifier.into());
        self
    }

    /// Sets the value that indicates whether the builder includes `"oauth_version"` parameter.
    /// The default is `true`.
    pub fn include_version(&mut self, include_version: bool) -> &mut Self {
        self.include_version = include_version;
        self
    }

    /// Generate `Authorization` header for OAuth.
    ///
    /// # Panics
    /// This function will panic if the `url` is not valid for HTTP or HTTPS.
    pub fn finish(self) -> OAuthAuthorizationHeader {
        let oauth_params = {
            let mut p = Vec::with_capacity(8);

            p.push(("oauth_consumer_key", self.consumer_key));
            p.push(("oauth_signature_method", self.signature_method.to_str().into()));
            p.push(("oauth_timestamp", self.timestamp.unwrap_or_else(gen_timestamp).to_string().into()));
            p.push(("oauth_nonce", match self.nonce {
                Some(x) => x,
                None => nonce().into()
            }));
            if let Some(x) = self.token { p.push(("oauth_token", x)) }
            if let Some(x) = self.callback { p.push(("oauth_callback", x)) }
            if let Some(x) = self.verifier { p.push(("oauth_verifier", x)) }
            if self.include_version { p.push(("oauth_version", "1.0".into())) }

            p
        };

        let signature = {
            let base_string = {
                let params = oauth_params.iter()
                    .map(|&(k, ref v)| (k.into(), v.clone()))
                    .chain(self.parameters.into_iter())
                    .chain(self.url.query_pairs());

                format!(
                    "{}&{}&{}",
                    self.method.to_ascii_uppercase(),
                    percent_encode(&base_string_url(self.url)),
                    percent_encode(&normalize_parameters(params))
                )
            };

            let mut key = format!("{}&", percent_encode(&self.consumer_secret));

            if let Some(x) = self.token_secret {
                key.extend(percent_encode(&x));
            }

            match self.signature_method {
                SignatureMethod::HmacSha1 =>
                    hmac(key.as_bytes(), base_string.as_bytes(), Sha1)
                        .to_base64(base64::STANDARD),
                SignatureMethod::Plaintext => key
            }
        };

        let mut oauth_params = self.realm.map(|x| ("realm".into(), x.into())).into_iter()
            .chain(oauth_params.into_iter())
            .chain(iter::once(("oauth_signature".into(), signature.into())));

        let mut result = String::new();
        let mut first = true;

        while let Some((k, v)) = oauth_params.next() {
            if first { first = false; }
            else { result.push(','); }

            write!(&mut result, "{}=\"{}\"",
                percent_encode(&k), percent_encode(&v)).unwrap();
        }

        OAuthAuthorizationHeader { auth_param: result }
    }
}

/// Generate `Authorization` header for OAuth.
/// The return value starts with `"OAuth "`.
///
/// # Panics
/// This function will panic if either `token` or `token_secret` is specified.
#[deprecated(since = "1.0.0", note = "Use OAuthAuthorizationHeaderBuilder")]
pub fn authorization_header<P>(method: &str, url: Url, realm: Option<&str>,
    consumer_key: &str, consumer_secret: &str, token: Option<&str>,
    token_secret: Option<&str>, signature_method: SignatureMethod,
    timestamp: &str, nonce: &str, callback: Option<&str>,
    verifier: Option<&str>, params: P)
    -> String where P: Iterator<Item = (String, String)>
{
    let mut builder = OAuthAuthorizationHeaderBuilder::new(method, &url, consumer_key, consumer_secret, signature_method);

    builder.request_parameters(params)
        .timestamp(timestamp.parse().expect("Couldn't parse `timestamp` parameter"))
        .nonce(nonce);

    match (token, token_secret) {
        (Some(x), Some(y)) => { builder.token(x, y); },
        (None, None) => (),
        (Some(_), None) | (None, Some(_)) => panic!("Both `token` and `token_secret` parameter are required")
    }

    if let Some(x) = realm { builder.realm(x); }
    if let Some(x) = callback { builder.callback(x); }
    if let Some(x) = verifier { builder.verifier(x); }

    builder.finish().to_string()
}
