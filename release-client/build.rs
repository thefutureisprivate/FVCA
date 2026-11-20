fn main() {
    const SOURCE: &str = "src/gpt/floor/tpm.c";
    println!("cargo:rerun-if-changed={SOURCE}");
    let mut build = cc::Build::new();
    let libraries = ["tss2-esys", "tss2-mu", "tss2-tctildr"].map(|package| {
        pkg_config::Config::new()
            .cargo_metadata(false)
            .probe(package)
            .expect("Fedora tpm2-tss-devel is required")
    });
    for library in &libraries {
        build.includes(&library.include_paths);
    }
    build
        .file(SOURCE)
        .flag("-std=c17")
        .extra_warnings(true)
        .warnings_into_errors(true)
        .compile("fvca_floor_tpm");
    // The shared libraries follow the static bridge that references them.
    for library in libraries {
        for path in library.link_paths {
            println!("cargo:rustc-link-search=native={}", path.display());
        }
        for name in library.libs {
            println!("cargo:rustc-link-lib={name}");
        }
    }
}
