use url::Url;
use super::*;

#[test]
fn signature_method_test() {
    assert_eq!(
        &SignatureMethod::HmacSha1.to_string()[..],
        "HMAC-SHA1"
    );
    assert_eq!(
        &SignatureMethod::Plaintext.to_string()[..],
        "PLAINTEXT"
    );
}

#[test]
fn percent_encode_test() {
    use super::percent_encode;

    assert_eq!(
        percent_encode("Ladies + Gentlemen").to_string(),
        "Ladies%20%2B%20Gentlemen"
    );
    assert_eq!(
        percent_encode("An encoded string!").to_string(),
        "An%20encoded%20string%21"
    );
    assert_eq!(
        percent_encode("Dogs, Cats & Mice").to_string(),
        "Dogs%2C%20Cats%20%26%20Mice"
    );
    assert_eq!(
        percent_encode("☃").to_string(),
        "%E2%98%83"
    );
}

#[test]
fn base_string_url_test() {
    use super::base_string_url;

    assert_eq!(
        base_string_url(
            &Url::parse("HTTP://EXAMPLE.COM:80/r%20v/X?id=123").unwrap()
        ),
        "http://example.com/r%20v/X"
    );
    assert_eq!(
        base_string_url(
            &Url::parse("https://www.example.net:8080/?q=1").unwrap()
        ),
        "https://www.example.net:8080/"
    );
}

#[test]
fn normalize_parameters_test() {
    use super::normalize_parameters;

    let params = [
        ("b5", "=%3D"),
        ("a3", "a"),
        ("c@", ""),
        ("a2", "r b"),
        ("oauth_consumer_key", "9djdj82h48djs9d2"),
        ("oauth_token", "kkk9d7dh3k39sjv7"),
        ("oauth_signature_method", "HMAC-SHA1"),
        ("oauth_timestamp", "137131201"),
        ("oauth_nonce", "7d8f3e4a"),
        ("c2", ""),
        ("a3", "2 q")
    ];

    assert_eq!(
        normalize_parameters(params.into_iter().map(|&(k, v)| (k.into(), v.into()))),
        concat!(
            "a2=r%20b&a3=2%20q&a3=a&b5=%3D%253D&c%40=&c2=&oauth_consumer_key=9dj",
            "dj82h48djs9d2&oauth_nonce=7d8f3e4a&oauth_signature_method=HMAC-SHA1",
            "&oauth_timestamp=137131201&oauth_token=kkk9d7dh3k39sjv7"
        )
    );
}

// TODO: Write test according to
// https://tools.ietf.org/html/rfc5849#section-1.2
