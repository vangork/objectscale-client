# ObjectScale-Client

This repo implements a Rust client for Dell ObjectScale management based on [ObjectScale 4.0.0.0 REST API Guide](https://dl.dell.com/downloads/400K3_ObjectScale-4.0.0.0---REST-API-Reference.zip).

It can also automatically genetate the according golang & python client via Rust FFI binding.

## Examples

[Install Rust](https://www.rust-lang.org/tools/install) before running examples for each language

### Rust

```
cargo run --example list_users
cargo run --example list_buckets
```

### Golang

```
cd c && cargo build --release
cd golang
go run examples/get_namespace.go
go run examples/list_namespaces.go
```

### Python

```
cd python
python -m venv .env
source .env/bin/activate
pip install maturin
maturin develop
python examples/list_buckets.py
python examples/create_bucket.py
python examples/get_bucket.py
python examples/update_bucket.py
python examples/delete_bucket.py
```

## Dev Tools
```
rustup component add clippy rustfmt
cargo install cargo-tarpaulin

cargo fmt
cargo clippy
cargo test
cargo doc
cargo tarpaulin --out Html
```
