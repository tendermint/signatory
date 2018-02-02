extern crate bindgen;

use std::env;
use std::path::{Path, PathBuf};

const YUBIHSM_SDK_ENV_VAR: &str = &"YUBIHSM_SDK";

fn main() {
    println!("cargo:rustc-link-lib=yubihsm");

    let yubihsm_sdk_path =
        env::var(YUBIHSM_SDK_ENV_VAR).expect(format!("{} environment variable unset", YUBIHSM_SDK_ENV_VAR));

    println!("cargo:rustc-link-search=native={}", Path::new(&yubihsm_sdk_path).join("lib").to_str().unwrap());

    let bindings = bindgen::Builder::default()
        .header(Path::new(&yubihsm_sdk_path).join("include/yubihsm.h").to_str().unwrap())
        .generate()
        .expect("Unable to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
