//! Yet Another OAuth 1.0 Client Library for Rust

extern crate rand;
extern crate rustc_serialize;
extern crate time;
extern crate url;

pub mod security;

use security::*;
use std::ascii::AsciiExt;
use std::borrow::Cow;
use std::cmp::Ordering;
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

#[derive(Debug, Clone)]
pub struct OAuthAuthorizationHeader {
    pub auth_param: String
}

impl fmt::Display for OAuthAuthorizationHeader {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "OAuth {}", self.auth_param)
    }
}

fn base_string_url(url: &Url) -> String {
    let scheme = url.scheme();

    assert!(match scheme { "http" | "https" => true, _ => false });

    let mut result = String::with_capacity(url.as_str().len());

    write!(&mut result, "{}://{}", scheme, url.host_str().expect("The host is None").to_ascii_lowercase()).unwrap();

    if let Some(p) = url.port() {
        match (scheme, p) {
            ("http", 80) | ("https", 443) => (),
            _ => write!(&mut result, ":{}", p).unwrap()
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

    mutparams.sort_by(|&(ref k1, ref v1), &(ref k2, ref v2)| {
        match k1.cmp(k2) {
            Ordering::Equal => v1.cmp(v2),
            x => x
        }
    });

    let mut result = String::new();

    if mutparams.len() > 0 {
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
    method: &'a str,
    url: &'a Url,
    parameters: Vec<(Cow<'a, str>, Cow<'a, str>)>,
    consumer_key: &'a str,
    consumer_secret: &'a str,
    signature_method: SignatureMethod,
    realm: Option<&'a str>,
    token: Option<(&'a str, &'a str)>,
    timestamp: Option<u64>,
    nonce: Option<&'a str>,
    callback: Option<&'a str>,
    verifier: Option<&'a str>,
    include_version: bool
}

impl<'a> OAuthAuthorizationHeaderBuilder<'a> {
    pub fn new(method: &'a str, url: &'a Url, consumer_key: &'a str, consumer_secret: &'a str, signature_method: SignatureMethod) -> Self
    {
        OAuthAuthorizationHeaderBuilder {
            method: method,
            url: url,
            parameters: Vec::new(),
            consumer_key: consumer_key,
            consumer_secret: consumer_secret,
            signature_method: signature_method,
            realm: None,
            token: None,
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

    pub fn realm(&mut self, realm: &'a str) -> &mut Self {
        self.realm = Some(realm);
        self
    }

    pub fn token(&mut self, token: &'a str, secret: &'a str) -> &mut Self {
        self.token = Some((token, secret));
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
    pub fn nonce(&mut self, nonce: &'a str) -> &mut Self {
        self.nonce = Some(nonce);
        self
    }

    pub fn callback(&mut self, callback: &'a str) -> &mut Self {
        self.callback = Some(callback);
        self
    }

    pub fn verifier(&mut self, verifier: &'a str) -> &mut Self {
        self.verifier = Some(verifier);
        self
    }

    /// Sets the value that indicates whether the builder includes `"oauth_version"` parameter.
    /// The default is `true`.
    pub fn include_version(&mut self, include_version: bool) -> &mut Self {
        self.include_version = include_version;
        self
    }

    fn oauth_parameters(&self) -> Vec<(&'static str, Cow<'a, str>)> {
        let mut p = Vec::with_capacity(8);

        p.push(("oauth_consumer_key", self.consumer_key.into()));
        p.push(("oauth_signature_method", self.signature_method.to_str().into()));
        p.push(("oauth_timestamp", self.timestamp.unwrap_or_else(gen_timestamp).to_string().into()));
        p.push(("oauth_nonce", match self.nonce {
            Some(x) => x.into(),
            None => nonce().into()
        }));
        if let Some((token, _)) = self.token { p.push(("oauth_token", token.into())) }
        if let Some(x) = self.callback { p.push(("oauth_callback", x.into())) }
        if let Some(x) = self.verifier { p.push(("oauth_verifier", x.into())) }
        if self.include_version { p.push(("oauth_version", "1.0".into())) }

        p
    }

    pub fn finish(self) -> OAuthAuthorizationHeader {
        let oauth_params = self.oauth_parameters();

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

            let mut key = format!("{}&", percent_encode(self.consumer_secret));

            if let Some((_, token_secret)) = self.token {
                write!(&mut key, "{}", percent_encode(token_secret)).unwrap();
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
