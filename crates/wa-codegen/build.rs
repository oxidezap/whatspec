fn main() {
    // Cargo can select rustc through configuration even when the test process
    // has no RUSTC override. Keep that exact default for runtime fixtures.
    for (source, destination) in [
        ("RUSTC", "WHATSPEC_FIXTURE_RUSTC"),
        ("TARGET", "WHATSPEC_FIXTURE_TARGET"),
    ] {
        println!("cargo:rerun-if-env-changed={source}");
        println!(
            "cargo:rustc-env={destination}={}",
            std::env::var(source).expect("Cargo build environment")
        );
    }
}
