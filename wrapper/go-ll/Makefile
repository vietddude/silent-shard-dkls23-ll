.PHONY: build clean test

build:
	cargo build --release

clean:
	cargo clean

test:
	cargo test

# Build for different platforms
build-linux:
	cargo build --release --target x86_64-unknown-linux-gnu

build-macos:
	cargo build --release --target x86_64-apple-darwin

build-windows:
	cargo build --release --target x86_64-pc-windows-gnu
