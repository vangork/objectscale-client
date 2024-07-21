# ObjectScale-Client

This repo provides a rust client for Dell ObjectScale which could be used for identity and access management (IAM), bucket and multi-tenancy management.

It also contains the according golang & python client via rust FFI binding.

## Examples

Some examples for each languages:

### rust

```
cd examples
cargo run --bin create_account
cargo run --bin delete_account
```

### golang

```
cd c && cargo build --release
cd golang
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
