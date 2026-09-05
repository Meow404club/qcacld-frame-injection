#!/usr/bin/env bash

set -euo pipefail

dir=$(cd -- "$(dirname -- "$0")" && pwd)
ndk=${ANDROID_NDK_ROOT:-$HOME/Android/Sdk/ndk/27.3.13750724}
compiler=$ndk/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android35-clang
output=$dir/send_stage1_packet

[[ -x $compiler ]] || { echo "Android NDK compiler unavailable: $compiler" >&2; exit 2; }

"$compiler" -std=c11 -O2 -Wall -Wextra -Werror \
	-o "$output" "$dir/send_stage1_packet.c"

file "$output" | grep -q 'ELF 64-bit LSB pie executable, ARM aarch64'
file "$output" | grep -q 'interpreter /system/bin/linker64'
printf 'android_sender=%s\n' "$output"
sha256sum "$output"
