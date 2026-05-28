use std::env;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=wrapper.h");
    println!("cargo:rerun-if-env-changed=PKG_CONFIG_PATH");
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_DPDK");

    // Skip bindgen/linking unless the `dpdk` feature is on so `cargo check`
    // works on hosts without DPDK (e.g. macOS). Real builds: --features dpdk.
    if env::var_os("CARGO_FEATURE_DPDK").is_none() {
        return;
    }

    let dpdk = pkg_config::Config::new()
        .statik(false)
        .probe("libdpdk")
        .expect(
            "libdpdk not found via pkg-config.\n\
             Install libdpdk-dev (e.g. `apt install libdpdk-dev` on Debian/Ubuntu)\n\
             or set PKG_CONFIG_PATH to a prefix containing libdpdk.pc.",
        );

    // numa and pthread aren't always pulled in by libdpdk.pc transitively.
    println!("cargo:rustc-link-lib=numa");
    println!("cargo:rustc-link-lib=pthread");

    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let static_fns_c = out_dir.join("dpdk_static_fns.c");

    let mut builder = bindgen::Builder::default()
        .header("wrapper.h")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .derive_default(true)
        .derive_debug(false)
        .generate_comments(false)
        .prepend_enum_name(false)
        .wrap_static_fns(true)
        .wrap_static_fns_path(&static_fns_c)
        .allowlist_function("rte_.*")
        .allowlist_function("_rte_.*")
        .allowlist_type("rte_.*")
        .allowlist_type("RTE_.*")
        .allowlist_var("RTE_.*")
        .allowlist_var("rte_.*")
        .clang_arg("-D__attribute__(x)=")
        .clang_arg("-D__extension__=");

    for include in &dpdk.include_paths {
        builder = builder.clang_arg(format!("-I{}", include.display()));
    }

    let bindings = builder
        .generate()
        .expect("bindgen failed to generate DPDK bindings");
    bindings
        .write_to_file(out_dir.join("bindings.rs"))
        .expect("failed to write bindings.rs");

    // bindgen --wrap-static-fns emits a C file with externs that call DPDK's
    // `static inline` hot path (rte_pktmbuf_alloc, rte_eth_rx_burst, ...).
    // Compile and link it so those functions are reachable from Rust.
    let mut cc = cc::Build::new();
    cc.file(&static_fns_c).include(".");
    for include in &dpdk.include_paths {
        cc.include(include);
    }
    for (k, v) in &dpdk.defines {
        match v {
            Some(val) => cc.define(k, val.as_str()),
            None => cc.define(k, None),
        };
    }
    cc.flag_if_supported("-march=native")
        .flag_if_supported("-Wno-unused-parameter")
        .flag_if_supported("-Wno-deprecated-declarations")
        .compile("dpdk_static_fns");

    let heap_size_str = env::var("HEAP_SIZE").unwrap_or_else(|_| "1GiB".into());

    let heap_size = parse_size(&heap_size_str);

    let generated = format!("pub const HEAP_SIZE: usize = {};", heap_size);

    std::fs::write("src/generated.rs", generated).expect("failed to write generated.rs");

    println!("cargo:rerun-if-env-changed=HEAP_SIZE");
}

fn parse_size(input: &str) -> usize {
    let s = input.trim();

    let units = [
        ("KiB", 1024usize),
        ("MiB", 1024usize.pow(2)),
        ("GiB", 1024usize.pow(3)),
        ("TiB", 1024usize.pow(4)),
        ("KB", 1000usize),
        ("MB", 1000usize.pow(2)),
        ("GB", 1000usize.pow(3)),
        ("TB", 1000usize.pow(4)),
        ("B", 1),
    ];

    for (suffix, multiplier) in units {
        if let Some(number) = s.strip_suffix(suffix) {
            let value: usize = number.trim().parse().expect("invalid numeric value");

            return value * multiplier;
        }
    }

    // No suffix => bytes
    s.parse().expect("invalid size")
}
