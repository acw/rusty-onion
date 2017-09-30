extern crate vergen;

use vergen::{OutputFns,vergen};

fn main() {
    assert!(vergen(OutputFns::all()).is_ok());
}
