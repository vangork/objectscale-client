# ObjectScale-Client

This repo provides a rust client for Dell ObjectScale which could be used for identity and access management (IAM), bucket and multi-tenancy management.

It also contains the according golang & python client via rust FFI binding.

## Examples

Some examples for each languages:

### rust

```
cargo run --example list_users
cargo run --example list_buckets
```

### golang

```
cd c && cargo build --release
cd golang
go run examples/get_namespace.go
go run examples/list_namespaces.go
```

### python

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

## Development
```
rustup component add clippy rustfmt
cargo install cargo-tarpaulin

cargo fmt
cargo clippy
cargo test
cargo doc
cargo tarpaulin --out Html
```
