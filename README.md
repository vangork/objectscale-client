# ObjectScale-Client

An [ObjectScale](https://www.dell.com/en-sg/shop/storage-servers-and-networking-for-business/sf/objectscale) REST API client library written in Rust, binding to different languages(Python, Golang, C) via foreign function interface.

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
