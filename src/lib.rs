//! Yet Another OAuth 1.0 Client Library for Rust
//!
//! # Examples
//! Basic sample:
//!
//! ```
//! # extern crate url;
//! # extern crate oauthcli;
//! use oauthcli::*;
//! # fn main() {
//! let url = url::Url::parse("http://example.com/").unwrap();
//! let header =
//!     OAuthAuthorizationHeaderBuilder::new(
//!         "GET", &url, "consumer", "secret", SignatureMethod::HmacSha1)
//!     .token("token", "secret")
//!     .finish();
//! # }
//! ```
//!
//! If you use for Twitter, because of Twitter's bug, use `finish_for_twitter` method,
//! and make sure to encode the request body with `OAUTH_ENCODE_SET`.
//! For more detail, see [this article](http://azyobuzin.hatenablog.com/entry/2015/04/18/232516) (Japanese).

extern crate base64;
extern crate crypto;
extern crate rand;
extern crate time;
extern crate url;
#[cfg(feature="hyper")] extern crate hyper;

#[cfg(test)] mod tests;

use std::ascii::AsciiExt;
use std::borrow::{Borrow, Cow};
use std::error::Error;
use std::fmt::{self, Write};
use std::iter;
use url::Url;
use url::percent_encoding::{EncodeSet, PercentEncode, utf8_percent_encode};

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

impl EncodeSet for OAUTH_ENCODE_SET {
    fn contains(&self, byte: u8) -> bool {
        !((byte >= 0x30 && byte <= 0x39)
        || (byte >= 0x41 && byte <= 0x5A)
        || (byte >= 0x61 && byte <= 0x7A)
        || byte == 0x2D || byte == 0x2E
        || byte == 0x5F || byte == 0x7E)
    }
}

fn percent_encode(input: &str) -> PercentEncode<OAUTH_ENCODE_SET> {
    utf8_percent_encode(input, OAUTH_ENCODE_SET)
}

#[derive(Copy, Debug, PartialEq, Eq, Clone, Hash)]
pub enum ParseOAuthAuthorizationHeaderError {
    /// The input is violating auth-param format.
    FormatError,
    /// The input is not completely escaped with `OAUTH_ENCODE_SET`.
    EscapeError
}

impl Error for ParseOAuthAuthorizationHeaderError {
    fn description(&self) -> &str {
        match *self {
            ParseOAuthAuthorizationHeaderError::FormatError => "The input is violating auth-param format",
            ParseOAuthAuthorizationHeaderError::EscapeError => "The input is not completely escaped with `OAUTH_ENCODE_SET`"
        }
    }
}

impl fmt::Display for ParseOAuthAuthorizationHeaderError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(self.description())
    }
}

/// `Authorization` header for OAuth.
///
/// If you enable `"hyper"` feature, this implements `hyper::header::Scheme` trait.
///
/// # Example
/// ```
/// # use oauthcli::OAuthAuthorizationHeader;
/// let header: OAuthAuthorizationHeader = "oauth_consumer_key=\"foo\"".parse().unwrap();
/// assert_eq!(header.to_string(), "OAuth oauth_consumer_key=\"foo\"");
/// ```
#[derive(Debug, Clone)]
pub struct OAuthAuthorizationHeader {
    s: String
}

impl OAuthAuthorizationHeader {
    /// `auth-param` in RFC 7235
    pub fn auth_param(&self) -> &str {
        &self.s
    }

    pub fn auth_param_owned(self) -> String {
        self.s
    }
}

impl fmt::Display for OAuthAuthorizationHeader {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        try!(f.write_str("OAuth "));
        f.write_str(&self.s)
    }
}

impl std::str::FromStr for OAuthAuthorizationHeader {
    type Err = ParseOAuthAuthorizationHeaderError;

    fn from_str(s: &str) -> Result<OAuthAuthorizationHeader, ParseOAuthAuthorizationHeaderError> {
        fn is_hex(x: u8) -> bool {
            (x >= b'0' && x <= b'9') ||
            (x >= b'A' && x <= b'F') ||
            (x >= b'a' && x <= b'f')
        }

        fn check(s: &str) -> bool {
            let mut i = s.as_bytes().iter();
            while let Some(&c) = i.next() {
                match c {
                    0x25 => {
                        if let (Some(&a), Some(&b)) = (i.next(), i.next()) {
                            if !(is_hex(a) && is_hex(b)) { return false; }
                        } else {
                            return false;
                        }
                    },
                    c => if OAUTH_ENCODE_SET.contains(c) { return false; }
                }
            }

            true
        }

        // Remove "OAuth" scheme
        let mut s = s.trim();
        if let Some(scheme) = s.split_whitespace().next() {
            if scheme.eq_ignore_ascii_case("OAuth") {
                s = &scheme[5..].trim_left();
            }
        }

        // Check each pair
        for pair in s.split(',').map(|x| x.trim()).filter(|x| x.len() > 0) {
            if let Some(equal_index) = pair.find('=') {
                if !check(pair[0..equal_index].trim_right()) {
                    return Err(ParseOAuthAuthorizationHeaderError::EscapeError);
                }

                let val = pair[equal_index+1..].trim_left();
                if !val.starts_with('"') || !val.ends_with('"') {
                    return Err(ParseOAuthAuthorizationHeaderError::FormatError);
                }
                if !check(&val[1..val.len()-1]) {
                    return Err(ParseOAuthAuthorizationHeaderError::EscapeError);
                }
            } else {
                return Err(ParseOAuthAuthorizationHeaderError::FormatError);
            }
        }

        Ok(OAuthAuthorizationHeader { s: s.to_owned() })
    }
}

#[cfg(feature="hyper")]
impl hyper::header::Scheme for OAuthAuthorizationHeader {
    fn scheme() -> Option<&'static str> {
        Some("OAuth")
    }

    fn fmt_scheme(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(&self.s)
    }
}

fn base_string_url(url: &Url) -> String {
    let scheme = url.scheme();

    let mut result = String::with_capacity(url.as_str().len());
    result.push_str(scheme);
    result.push_str("://");
    result.push_str(url.host_str().expect("The host is None"));

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

struct PercentEncodedParameters<'a>(Vec<(Cow<'a, str>, Cow<'a, str>)>);

fn percent_encode_parameters<'a, P>(params: P) -> PercentEncodedParameters<'a>
    where P: Iterator<Item = (Cow<'a, str>, Cow<'a, str>)>
{
    PercentEncodedParameters(
        params
            .map(|(k, v)| (percent_encode(&k).to_string().into(), percent_encode(&v).to_string().into()))
            .collect()
    )
}

fn normalize_parameters<'a>(params: PercentEncodedParameters<'a>) -> String {
    let mut mutparams = params.0;
    let mut result = String::new();

    if mutparams.len() > 0 {
        mutparams.sort();

        let mut first = true;
        for (key, val) in mutparams.into_iter() {
            if first { first = false; }
            else { result.push('&'); }

            result.push_str(&key);
            result.push('=');
            result.push_str(&val);
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
    use rand::Rng;

    rand::thread_rng().gen_ascii_chars()
        .take(42).collect()
}

fn hmac_sha1_base64(key: &[u8], msg: &[u8]) -> String {
    use crypto::mac::Mac;
    use crypto::{hmac, sha1};

    let mut hmac = hmac::Hmac::new(sha1::Sha1::new(), key);
    debug_assert_eq!(20, hmac.output_bytes());

    hmac.input(msg);
    
    let mut mac = [0u8; 20];
    hmac.raw_result(&mut mac);

    base64::encode(&mac)
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

    fn signature(&self, oauth_params: &[(&'a str, &'a str)], for_twitter: bool) -> String {
        let mut key: String = percent_encode(&self.consumer_secret).collect();
        key.push('&');

        if let &Some(ref x) = &self.token_secret {
            key.extend(percent_encode(&x));
        }

        match &self.signature_method {
            &SignatureMethod::HmacSha1 => {
                let params = oauth_params.iter()
                    .map(|&(k, v)| (k.into(), v.into()))
                    .chain(self.parameters.iter()
                        .map(|&(ref k, ref v)| (Cow::Borrowed(k.borrow()), Cow::Borrowed(v.borrow()))));

                let params =
                    if for_twitter {
                        // Workaround for Twitter: don't re-encode the query
                        let PercentEncodedParameters(mut x) = percent_encode_parameters(params);

                        if let Some(query) = self.url.query() {
                            for pair in query.split('&').filter(|x| x.len() > 0) {
                                let mut pair_iter = pair.splitn(2, '=');
                                let key = pair_iter.next().unwrap();
                                let val = pair_iter.next().unwrap_or("");
                                x.push((key.into(), val.into()));
                            }
                        }

                        PercentEncodedParameters(x)
                    } else {
                        percent_encode_parameters(params.chain(self.url.query_pairs()))
                    };

                let mut base_string = self.method.to_ascii_uppercase();
                base_string.push('&');
                base_string.extend(percent_encode(&base_string_url(self.url)));
                base_string.push('&');
                base_string.extend(percent_encode(&normalize_parameters(params)));

                hmac_sha1_base64(key.as_bytes(), base_string.as_bytes())
            },
            &SignatureMethod::Plaintext => key
        }
    }

    fn finish_impl(&self, for_twitter: bool) -> OAuthAuthorizationHeader {
        let tmp_timestamp = self.timestamp.unwrap_or_else(gen_timestamp).to_string();
        let tmp_nonce;
        let oauth_params = {
            let mut p = Vec::with_capacity(8);

            p.push(("oauth_consumer_key", self.consumer_key.borrow()));
            if let Some(ref x) = self.token { p.push(("oauth_token", x.borrow())) }
            p.push(("oauth_signature_method", self.signature_method.to_str()));
            p.push(("oauth_timestamp", &tmp_timestamp));
            p.push(("oauth_nonce", match &self.nonce {
                &Some(ref x) => x.borrow(),
                _ => {
                    tmp_nonce = nonce();
                    &tmp_nonce
                }
            }));
            if let &Some(ref x) = &self.callback { p.push(("oauth_callback", x.borrow())) }
            if let &Some(ref x) = &self.verifier { p.push(("oauth_verifier", x.borrow())) }
            if self.include_version { p.push(("oauth_version", "1.0")) }

            p
        };

        let signature = self.signature(&oauth_params, for_twitter);

        let mut oauth_params = self.realm.as_ref()
            .map(|x| ("realm", x.borrow()))
            .into_iter()
            .chain(oauth_params.into_iter())
            .chain(iter::once(("oauth_signature", &signature[..])));

        let mut result = String::new();
        let mut first = true;

        while let Some((k, v)) = oauth_params.next() {
            if first { first = false; }
            else { result.push(','); }

            write!(&mut result, "{}=\"{}\"",
                percent_encode(k), percent_encode(v)).unwrap();
        }

        OAuthAuthorizationHeader { s: result }
    }

    /// Generate `Authorization` header for OAuth.
    ///
    /// # Panics
    /// This function will panic if `url` is not valid for HTTP or HTTPS.
    pub fn finish(&self) -> OAuthAuthorizationHeader {
        self.finish_impl(false)
    }

    /// Generate `Authorization` header for Twitter.
    ///
    /// # Panics
    /// This function will panic if `url` is not valid for HTTP or HTTPS.
    pub fn finish_for_twitter(&self) -> OAuthAuthorizationHeader {
        self.finish_impl(true)
    }
}

/// Generate `Authorization` header for OAuth.
/// The return value starts with `"OAuth "`.
///
/// # Panics
/// This function will panic if:
/// - either `token` or `token_secret` is specified.
/// - `timestamp` is not valid for u64.
/// - `url` is not valid for HTTP or HTTPS.
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
        _ => panic!("Both `token` and `token_secret` parameter are required")
    }

    if let Some(x) = realm { builder.realm(x); }
    if let Some(x) = callback { builder.callback(x); }
    if let Some(x) = verifier { builder.verifier(x); }

    builder.finish().to_string()
}
