use url::Url;
use super::*;

#[test]
fn signature_method_test() {
    assert_eq!(
        SignatureMethod::HmacSha1.to_string(),
        "HMAC-SHA1"
    );
    assert_eq!(
        SignatureMethod::Plaintext.to_string(),
        "PLAINTEXT"
    );
}

#[test]
fn percent_encode_test() {
    use super::percent_encode;

    // https://dev.twitter.com/oauth/overview/percent-encoding-parameters

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
fn from_str_test() {
    fn f(s: &str) -> Result<OAuthAuthorizationHeader, ParseOAuthAuthorizationHeaderError> {
        s.parse()
    }

    assert!(f(",a = \"a%2F\" , b = \"b\",,").is_ok());
    assert!(f("a").is_err());
    assert!(f("a=\"+a\"").is_err());

    assert!(f(r#"oauth_consumer_key="xvz1evFS4wEEPTGEFPHBog", 
              oauth_nonce="kYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg", 
              oauth_signature="tnnArxj06cWHq44gCs1OSKk%2FjLY%3D", 
              oauth_signature_method="HMAC-SHA1", 
              oauth_timestamp="1318622958", 
              oauth_token="370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb", 
              oauth_version="1.0""#).is_ok());
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
    use super::{normalize_parameters, percent_encode_parameters};

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
        normalize_parameters(
            percent_encode_parameters(
                params.into_iter().map(|&(k, v)| (k.into(), v.into()))
            )
        ),
        concat!(
            "a2=r%20b&a3=2%20q&a3=a&b5=%3D%253D&c%40=&c2=&oauth_consumer_key=9dj",
            "dj82h48djs9d2&oauth_nonce=7d8f3e4a&oauth_signature_method=HMAC-SHA1",
            "&oauth_timestamp=137131201&oauth_token=kkk9d7dh3k39sjv7"
        )
    );
}

// https://tools.ietf.org/html/rfc5849#section-1.2

#[test]
fn example_initiate() {
    let url = Url::parse("https://photos.example.net/initiate").unwrap();
    let result = OAuthAuthorizationHeaderBuilder::new("POST", &url, "dpf43f3p2l4k3l03", "kd94hf93k423kf44", SignatureMethod::HmacSha1)
        .realm("Photos")
        .timestamp(137131200)
        .nonce("wIjqoS")
        .callback("http://printer.example.com/ready")
        .include_version(false)
        .finish();

    assert_eq!(
        result.to_string(),
        "OAuth realm=\"Photos\",\
        oauth_consumer_key=\"dpf43f3p2l4k3l03\",\
        oauth_signature_method=\"HMAC-SHA1\",\
        oauth_timestamp=\"137131200\",\
        oauth_nonce=\"wIjqoS\",\
        oauth_callback=\"http%3A%2F%2Fprinter.example.com%2Fready\",\
        oauth_signature=\"74KNZJeDHnMBp0EMJ9ZHt%2FXKycU%3D\""
    );
}

#[test]
fn example_token() {
    let url = Url::parse("https://photos.example.net/token").unwrap();
    let result = OAuthAuthorizationHeaderBuilder::new("POST", &url, "dpf43f3p2l4k3l03", "kd94hf93k423kf44", SignatureMethod::HmacSha1)
        .realm("Photos")
        .token("hh5s93j4hdidpola", "hdhd0244k9j7ao03")
        .timestamp(137131201)
        .nonce("walatlh")
        .verifier("hfdp7dh39dks9884")
        .include_version(false)
        .finish();

    assert_eq!(
        result.to_string(),
        "OAuth realm=\"Photos\",\
        oauth_consumer_key=\"dpf43f3p2l4k3l03\",\
        oauth_token=\"hh5s93j4hdidpola\",\
        oauth_signature_method=\"HMAC-SHA1\",\
        oauth_timestamp=\"137131201\",\
        oauth_nonce=\"walatlh\",\
        oauth_verifier=\"hfdp7dh39dks9884\",\
        oauth_signature=\"gKgrFCywp7rO0OXSjdot%2FIHF7IU%3D\""
    );
}

#[test]
fn example_photos() {
    let url = Url::parse("http://photos.example.net/photos?file=vacation.jpg&size=original").unwrap();
    let result = OAuthAuthorizationHeaderBuilder::new("GET", &url, "dpf43f3p2l4k3l03", "kd94hf93k423kf44", SignatureMethod::HmacSha1)
        .realm("Photos")
        .token("nnch734d00sl2jdk", "pfkkdhi9sl3r4s00")
        .timestamp(137131202)
        .nonce("chapoH")
        .include_version(false)
        .finish();

    assert_eq!(
        result.to_string(),
        "OAuth realm=\"Photos\",\
        oauth_consumer_key=\"dpf43f3p2l4k3l03\",\
        oauth_token=\"nnch734d00sl2jdk\",\
        oauth_signature_method=\"HMAC-SHA1\",\
        oauth_timestamp=\"137131202\",\
        oauth_nonce=\"chapoH\",\
        oauth_signature=\"MdpQcU8iPSUjWoN%2FUDMsK2sui9I%3D\""
    );
}
