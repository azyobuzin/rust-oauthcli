extern crate futures;
extern crate hyper;
extern crate hyper_tls;
extern crate oauthcli;
extern crate tokio_core;

use futures::{future, Future, Stream};
use hyper::header;
use oauthcli::{OAuthAuthorizationHeaderBuilder, SignatureMethod};
use oauthcli::url::Url;

fn main() {
    let req = {
        let url = Url::parse("https://api.twitter.com/1.1/statuses/user_timeline.json?screen_name=azyobuzin").unwrap();

        // @imgazyobuzi readonly token
        let auth_header = OAuthAuthorizationHeaderBuilder::new(
            "GET", &url, "uiYQy5R2RJFZRZ4zvSk7A", "qzDldacVrcyXbp8pBerf1LBfnQXmkPKmyLVGGLus8", SignatureMethod::HmacSha1)
            .token("862962650-rIcjsj0j9ZJ8khPVA8jZTtEJuq7YYDBDpx6fOAgb", "kbMQjdVldI6tFOST3SVjmyAtG1D0oCkCpL6vBv1FtA")
            .finish_for_twitter();

        let mut req = hyper::Request::new(hyper::Get, url.as_str().parse().unwrap());
        req.headers_mut().set(header::Authorization(auth_header.to_string()));
        req
    };

    let mut core = tokio_core::reactor::Core::new().unwrap();
    let handle = core.handle();
    let client = hyper::Client::configure()
        .connector(hyper_tls::HttpsConnector::new(1, &handle).unwrap())
        .build(&handle);

    let f = client.request(req)
        .and_then(|res| {
            let buf = match res.headers().get::<header::ContentLength>() {
                Some(&header::ContentLength(x)) => Vec::with_capacity(x as usize),
                None => Vec::new(),
            };

            res.body().fold(buf, |mut buf, chunk| {
                buf.extend(chunk);
                future::ok::<_, hyper::Error>(buf)
            })
        })
        .and_then(|buf|
            String::from_utf8(buf)
                .map_err(|e| hyper::Error::Utf8(e.utf8_error()))
        );

    let res = core.run(f).unwrap();
    println!("{}", res);
}
