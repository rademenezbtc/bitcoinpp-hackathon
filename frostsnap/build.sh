#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
SOURCE="$ROOT/.frostsnap-build"
REV=538b0ec0832de92de98b1f58c556a0ea559ab9f4
if [ -e "$SOURCE" ]; then
  echo "Build checkout already exists: $SOURCE. Rebuild there with cargo; this script will not overwrite it." >&2
  exit 1
fi
git clone --filter=blob:none --no-checkout https://github.com/frostsnap/frostsnap.git "$SOURCE"
git -C "$SOURCE" fetch origin refs/pull/640/head
git -C "$SOURCE" checkout --detach "$REV"
git -C "$SOURCE" apply "$ROOT/frostsnap/workspace.patch"
mkdir -p "$SOURCE/tools"
cp -R "$ROOT/frostsnap/sp_bridge" "$SOURCE/tools/sp_bridge"
cd "$SOURCE"
cargo +1.95.0 build --locked -p frostsnap_sp_bridge
cargo +1.95.0 test --locked -p frostsnap_sp_bridge
echo "Bridge binaries: $SOURCE/target/debug/"
