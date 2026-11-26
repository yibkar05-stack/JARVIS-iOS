#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
export LC_ALL=C TZ=UTC
export CODE_SIGNING_ALLOWED=NO

xcodebuild -version
sdk="$(xcrun --sdk iphoneos --show-sdk-path)"
mkdir -p dist
stage="$(mktemp -d "$PWD/dist/.stage.XXXXXXXX")"
trap 'rm -rf -- "$stage"' EXIT
app="$stage/Payload/JARVIS.app"
mkdir -p "$app"
cp App/Info.plist "$app/Info.plist"
plutil -lint "$app/Info.plist"

xcrun --sdk iphoneos swiftc -sdk "$sdk" -target arm64-apple-ios15.0 \
    -swift-version 5 -O -parse-as-library -module-name JARVIS \
    -Xlinker -no_adhoc_codesign -Xlinker -no_uuid \
    App/Agent.swift App/JarvisApp.swift -o "$app/JARVIS"

xcrun lipo "$app/JARVIS" -verify_arch arm64
load_commands="$(xcrun otool -l "$app/JARVIS")"
if grep -q 'LC_CODE_SIGNATURE' <<< "$load_commands"; then
    echo "El ejecutable contiene una firma" >&2
    exit 1
fi

ipa="$PWD/dist/JARVIS-unsigned.ipa"
touch -t 200001010000 "$app/JARVIS" "$app/Info.plist"
(
    cd "$stage"
    zip -X -q -9 "$stage/JARVIS-unsigned.ipa" Payload/JARVIS.app/Info.plist Payload/JARVIS.app/JARVIS
)
unzip -t "$stage/JARVIS-unsigned.ipa"
mv -f "$stage/JARVIS-unsigned.ipa" "$ipa"
(
    cd dist
    shasum -a 256 JARVIS-unsigned.ipa > JARVIS-unsigned.ipa.sha256
    shasum -a 256 -c JARVIS-unsigned.ipa.sha256
)
