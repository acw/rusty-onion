use vergen::vergen;

fn main() {
    let mut flags = OutputFns::all();
    assert!(vergen(flags).is_ok());
}
