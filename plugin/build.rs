//! Builds the C++ shim against the IDA SDK named by `IDASDK` (the SDK's `src` folder, e.g. a
//! checkout of HexRaysSA/ida-sdk at a release tag). The SDK version decides which IDA the DLL is for.

use std::{env, fs, path::PathBuf};

fn main() {
    println!("cargo:rerun-if-env-changed=IDASDK");
    println!("cargo:rerun-if-changed=src/shim.cpp");
    println!("cargo:rerun-if-changed=src/settings_ui.hpp");
    println!("cargo:rerun-if-changed=src/syscall_ui.hpp");
    let sdk = PathBuf::from(env::var("IDASDK").expect("set IDASDK to the IDA SDK `src` folder"));
    let pro_h = fs::read_to_string(sdk.join("include/pro.h")).expect("IDASDK has no include/pro.h");
    let version = pro_h
        .lines()
        .find_map(|l| l.strip_prefix("#define IDA_SDK_VERSION"))
        .map(str::trim)
        .expect("IDA_SDK_VERSION not found in pro.h");
    println!("cargo:rustc-env=IDA_SDK_VERSION={version}");

    // pro.lib from x64_win_64_s is built with the static CRT, so the whole DLL must be /MT.
    assert!(
        env::var("CARGO_CFG_TARGET_FEATURE").unwrap_or_default().contains("crt-static"),
        "build with the static CRT (see .cargo/config.toml)"
    );

    cc::Build::new()
        .cpp(true)
        .std("c++20")
        .file("src/shim.cpp")
        .include(sdk.join("include"))
        .define("__EA64__", None)
        .define("NO_OBSOLETE_FUNCS", None)
        .flag("/EHsc")
        .warnings(false)
        .compile("ntrays_shim");

    println!("cargo:rustc-link-search=native={}", sdk.join("lib/x64_win_64").display());
    println!("cargo:rustc-link-search=native={}", sdk.join("lib/x64_win_64_s").display());
    println!("cargo:rustc-link-lib=dylib=ida");
    println!("cargo:rustc-link-lib=static=pro");
    // PLUGIN lives in the shim's static library; nothing in Rust references it, so force it in.
    println!("cargo:rustc-cdylib-link-arg=/INCLUDE:PLUGIN");
}
