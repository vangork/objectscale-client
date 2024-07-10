mod parser;

use anyhow::Result;
use parser::Parser;
use std::env;
use std::path::PathBuf;

fn main() -> Result<()> {
    let current_dir = env::var("CARGO_MANIFEST_DIR")?;
    let crate_dir: PathBuf = PathBuf::from(&current_dir).join("..").join("src");

    let parser = Parser::parse(&crate_dir)?;
    parser.print();
    Ok(())
}
