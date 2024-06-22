# ObjectScale-Client

This repo demonstrate how to binding Rust based ObjectScale Management Client to other languages safely and productively

It generates Rust FFI bindings to golang & python libraries.

### rust

```
cd examples
cargo run --bin create_account
cargo run --bin delete_account
```

### golang

```
cd golang
cargo build --release
go build examples/create_account/main.go
./main
go build examples/delete_account/main.go
./main
```

### python

```
cd python
python -m venv .env
source .env/bin/activate
pip install maturin
maturin develop
python examples/create_account.py
python examples/delete_account.py
```

### development
```
rustup component add clippy rustfmt
cargo install cargo-tarpaulin

cargo fmt
cargo clippy
cargo test
cargo doc
cargo tarpaulin --out Html
```
