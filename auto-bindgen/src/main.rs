use anyhow::Result;
use auto_bindgen::gen::Bindgen;
use std::env;
use std::path::PathBuf;

fn main() -> Result<()> {
    let current_dir = env::var("CARGO_MANIFEST_DIR")?;
    let current_dir = PathBuf::from(&current_dir);
    let root_dir = current_dir.join("..");
    let crate_dir: PathBuf = root_dir.join("src");

    let bindgen = Bindgen::parse(&crate_dir)?;

    //let gen_dir = current_dir.join("gen");
    //bindgen.print(&gen_dir);
    bindgen.print(&root_dir);
    Ok(())
}
