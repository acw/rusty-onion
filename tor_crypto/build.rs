extern crate gcc;

fn main() {
    gcc::Build::new()
    .file("c/curve25519.c")
    .include("c")
    .compile("tc_curve25519");
}
