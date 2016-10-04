#[cfg(feature = "hyper")]
extern crate hyper;
extern crate oauthcli;
extern crate url;

#[cfg(feature = "hyper")]
fn main() {
    use std::io::Read;
    use url::Url;
    use oauthcli::{OAuthAuthorizationHeaderBuilder, SignatureMethod};

    let url = Url::parse("https://api.twitter.com/1.1/statuses/user_timeline.json?screen_name=azyobuzin").unwrap();

    // @imgazyobuzi readonly token
    let auth_header = OAuthAuthorizationHeaderBuilder::new(
        "GET", &url, "uiYQy5R2RJFZRZ4zvSk7A", "qzDldacVrcyXbp8pBerf1LBfnQXmkPKmyLVGGLus8", SignatureMethod::HmacSha1)
        .token("862962650-rIcjsj0j9ZJ8khPVA8jZTtEJuq7YYDBDpx6fOAgb", "kbMQjdVldI6tFOST3SVjmyAtG1D0oCkCpL6vBv1FtA")
        .finish_for_twitter();
    
    let mut res = String::new();
    hyper::Client::new().get(url)
        .header(hyper::header::Authorization(auth_header))
        .send()
        .unwrap()
        .read_to_string(&mut res)
        .unwrap();

    println!("{}", res);
}

#[cfg(not(feature = "hyper"))]
fn main() {
    println!("Comple with `hyper` feature to run this example")
}
