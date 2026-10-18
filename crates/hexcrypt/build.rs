// rust-embed needs the folder to exist even before the web UI is built.
fn main() {
    std::fs::create_dir_all("dist").unwrap();
    println!("cargo:rerun-if-changed=dist");
}
