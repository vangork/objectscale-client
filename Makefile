default: auto-bindgen

auto-bindgen:
	cd auto-bindgen; cargo run
	cargo fmt
	cd golang && go fmt ./...

python:
	cd python; source .env/bin/activate; pip install .

golang:
	cd c && cargo build --release
