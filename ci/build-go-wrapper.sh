#!/bin/sh

set -e

usage() {
    echo "build-go-wrapper.sh [ -t target ] [ -o output ]";
    echo "  -t target: Rust target (default: current host)"
    echo "  -o output: Output directory (default: dist/go-ll)"
    exit 1
}

TARGET=""
OUTPUT_DIR="dist/go-ll"

while getopts "t:o:h" opt; do
    case "${opt}" in
        t)
            TARGET=${OPTARG}
            ;;
        o)
            OUTPUT_DIR=${OPTARG}
            ;;
        h)
            usage
            ;;
        *)
            usage
            ;;
    esac
done

cd "$(dirname "$0")/.."

echo "Building Rust library..."
cd wrapper/go-ll

if [ -n "${TARGET}" ]; then
    cargo build --release --target "${TARGET}"
    TARGET_DIR="target/${TARGET}/release"
else
    cargo build --release
    TARGET_DIR="target/release"
fi

# Create symlink for CGO
mkdir -p target/release
case "${TARGET}" in
    *linux*)
        ln -sf "../../../../${TARGET_DIR}/libdkls_go_ll.so" target/release/libdkls_go_ll.so
        ;;
    *darwin*)
        ln -sf "../../../../${TARGET_DIR}/libdkls_go_ll.dylib" target/release/libdkls_go_ll.dylib
        ;;
    *windows*)
        ln -sf "../../../../${TARGET_DIR}/dkls_go_ll.dll" target/release/dkls_go_ll.dll
        ;;
    *)
        # Default: try to find the library
        if [ -f "../../../${TARGET_DIR}/libdkls_go_ll.so" ]; then
            ln -sf "../../../../${TARGET_DIR}/libdkls_go_ll.so" target/release/libdkls_go_ll.so
        elif [ -f "../../../${TARGET_DIR}/libdkls_go_ll.dylib" ]; then
            ln -sf "../../../../${TARGET_DIR}/libdkls_go_ll.dylib" target/release/libdkls_go_ll.dylib
        fi
        ;;
esac

echo "Building Go package..."
cd go
export CGO_ENABLED=1

# Build the package
go build -v ./...

# Run tests
echo "Running Go tests..."
go test -v ./...

# Create output directory
mkdir -p "../../${OUTPUT_DIR}"

# Copy library to output
case "${TARGET}" in
    *linux*)
        cp "../${TARGET_DIR}/libdkls_go_ll.so" "../../${OUTPUT_DIR}/"
        ;;
    *darwin*)
        cp "../${TARGET_DIR}/libdkls_go_ll.dylib" "../../${OUTPUT_DIR}/"
        ;;
    *windows*)
        cp "../${TARGET_DIR}/dkls_go_ll.dll" "../../${OUTPUT_DIR}/"
        ;;
esac

echo "Build complete! Output: ${OUTPUT_DIR}"

