//! Yet Another OAuth 1.0 Client Library for Rust

extern crate rand;
extern crate rustc_serialize;
extern crate time;
extern crate url;

mod security;

use security::*;
use std::ascii::AsciiExt;
use std::borrow::Cow;
use std::cmp::Ordering;
use std::fmt::{self, Write};
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

pub struct OAuthAuthorizationHeader {
    pub parameter: String
}

impl fmt::Display for OAuthAuthorizationHeader {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "OAuth {}", self.parameter)
    }
}

impl fmt::Debug for OAuthAuthorizationHeader {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self, f)
    }
}

pub struct OAuthHeaderBuilder<'a> {
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

fn signature_base_string<'a>(method: &'a str, url: &Url, oauth_params: &[(&'static str, Cow<'a, str>)], other_params: Vec<(Cow<'a, str>, Cow<'a, str>)>) -> String {
    let params = oauth_params.iter()
        .map(|&(k, ref v)| (k.into(), v.clone()))
        .chain(other_params.into_iter())
        .chain(url.query_pairs());

    format!(
        "{}&{}&{}",
        method.to_ascii_uppercase(),
        percent_encode(&base_string_url(url)),
        percent_encode(&normalize_parameters(params))
    )
}

fn gen_timestamp() -> u64 {
    let x = time::now_utc().to_timespec().sec;
    assert!(x > 0);
    return x as u64;
}

fn gen_nonce() -> String {
    rand::thread_rng().gen_ascii_chars()
        .take(42).collect()
}

impl<'a> OAuthHeaderBuilder<'a> {
    pub fn new<K, V, P>(method: &'a str, url: &'a Url, parameters: P, consumer_key: &'a str, consumer_secret: &'a str, signature_method: SignatureMethod) -> OAuthHeaderBuilder<'a>
        where K: Into<Cow<'a, str>>, V: Into<Cow<'a, str>>, P: Iterator<Item=(K, V)>
    {
        OAuthHeaderBuilder {
            method: method,
            url: url,
            parameters: parameters.map(|(k, v)| (k.into(), v.into())).collect(),
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
            None => gen_nonce().into()
        }));
        if let Some((token, _)) = self.token { p.push(("oauth_token", token.into())) }
        if let Some(x) = self.callback { p.push(("oauth_callback", x.into())) }
        if let Some(x) = self.verifier { p.push(("oauth_verifier", x.into())) }
        if self.include_version { p.push(("oauth_version", "1.0".into())) }

        p
    }

    fn signature(&self, base_string: String) -> String {
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
    }

    pub fn finish(self) -> OAuthAuthorizationHeader {
        let oauth_params = self.oauth_parameters();
        let base_string = signature_base_string(self.method, self.url, &oauth_params, self.parameters);

        unimplemented!()
    }
}
