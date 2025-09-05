auto-bindgen:
	cd auto-bindgen; cargo run
	cargo fmt
	cd golang && go fmt ./...
