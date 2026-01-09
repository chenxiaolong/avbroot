#!/bin/bash

set -eu

cd "$(dirname "${BASH_SOURCE[0]}")"

pushd ../.. >/dev/null
cargo build
popd >/dev/null

avbroot=$(pwd)/../../target/debug/avbroot

generate_corpus() {
    local generator=${1}
    local corpus_dir=${2}
    local suffix=${3}

    for dir in "${corpus_dir}"/*/; do
        output=${dir%/}${suffix}
        output=../hfuzz_workspace/${output/\//\/input\/}
        abs_output=$(pwd)/${output}

        echo "# ${dir} -> ${output}"

        mkdir -p "${abs_output%/*}"

        pushd "${dir}" >/dev/null
        "${generator}" "${abs_output}"
        popd >/dev/null

        echo
    done
}

generate_avb_image() {
    "${avbroot}" avb pack -q -o "${1}"
}

generate_boot_image() {
    if [[ -d vts_signature ]]; then
        pushd vts_signature >/dev/null
        "${avbroot}" avb pack -q -o ../vts_signature.img
        popd >/dev/null
    fi

    "${avbroot}" boot pack -q -o "${1}"
}

generate_cpio_image() {
    "${avbroot}" cpio pack -q -o "${1}"
}

generate_fec_image() {
    "${avbroot}" fec generate -i input.img -f "${1}"
}

generate_lp_image() {
    "${avbroot}" lp pack -q -o "${1}"
}

generate_sparse_image() {
    "${avbroot}" sparse pack -q -i input.img -o "${1}"
}

generate_corpus generate_avb_image avb .img
generate_corpus generate_boot_image bootimage .img
generate_corpus generate_cpio_image cpio .cpio
generate_corpus generate_fec_image fec .fec
generate_corpus generate_lp_image lp .img
generate_corpus generate_sparse_image sparse .img
