// Links against the CMake-built libsublimation.a (montauk-mcp is a sibling
// top-level dir to build/, same layout as montauk-kernel/, no CMakeLists.txt
// involvement -- montauk-mcp is built and installed entirely by cargo /
// install.py). MONTAUK_BUILD_DIR overrides the default relative path for
// out-of-tree builds.
fn main() {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let build_dir = std::env::var("MONTAUK_BUILD_DIR")
        .unwrap_or_else(|_| format!("{manifest_dir}/../build"));

    println!("cargo:rustc-link-search=native={build_dir}");
    println!("cargo:rustc-link-lib=static=sublimation");
    // sublimation's own CMakeLists.txt links these; static linking needs them too.
    println!("cargo:rustc-link-lib=dylib=pthread");
    println!("cargo:rustc-link-lib=dylib=m");
    println!("cargo:rerun-if-changed={build_dir}/libsublimation.a");
}
