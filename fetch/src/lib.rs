extern crate hyper;
extern crate tokio_core;

use std::io;
use tokio_core::reactor::Core;

#[derive(Debug)]
pub enum FetchErrors<E> {
    IOError(io::Error),
    HTTPError(hyper::Error),
    DecodeError(io::Error),
    Timeout,
    ParseError(E)
}

pub fn new_core() -> Core {
    match Core::new() {
        Ok(v) => v,
        Err(e) => panic!("Couldn't create tokio Core: {:?}", e)
    }
}

/* FIXME: I really wanted this to be a function, but there's some odd trait
 * constraints around the hyper client that don't seem to allow it. As a
 * result, a macro seems to be about the best I can do. If someone wants to
 * come back to this, I'd love to see a functional version, as I think it'd
 * cut down on compile times tremendously. */
#[macro_export]
macro_rules! fetch_and_parse {
    ( $handle: expr, $uri: expr, $timeout_secs: expr, $parser: expr ) => ({
        let buffer = Vec::new();
        let decoder = ZlibDecoder::new(buffer);
        let client = Client::new(&$handle);
        let timeout_len = Duration::from_secs($timeout_secs);
        let timeout = Timeout::new(timeout_len, &$handle).unwrap();
        client.get($uri)
              .map(move |resp| resp.body())
              .flatten_stream()
              .map_err(move |he| FetchErrors::HTTPError(he))
              .fold(decoder, move |mut dec, c| match dec.write_all(&c) {
                   Err(e) => Err(FetchErrors::DecodeError(e)),
                   Ok(_)  => Ok(dec)
               })
              .and_then(move |dec| match dec.finish() {
                   Err(e)    => Err(FetchErrors::DecodeError(e)),
                   Ok(block) => Ok(block.clone())
               })
              .and_then(move |ascii| match $parser(&ascii) {
                   Err(e)    => Err(FetchErrors::ParseError(e)),
                   Ok(auth)  => Ok(auth)
               })
              .select2(timeout)
              .then(move |res| match res {
                   Ok(Either::A((v, _))) => Ok(v),
                   Ok(Either::B((_, _))) => Err(FetchErrors::Timeout),
                   Err(Either::A((e,_))) => Err(e),
                   Err(Either::B((e,_))) => Err(FetchErrors::IOError(e))
              })
    })
}
