#!/bin/sh
set -eu

image="${1:-fortag-native-runtime:local}"
context="${2:-.}"

docker build --target runtime -t "$image" -f "$context/Dockerfile" "$context"
docker run --rm --entrypoint /bin/sh "$image" -ec '
    test -x /app/scanner
    ! apk info -e nmap
    ! apk info -e nmap-scripts
    test ! -e /usr/bin/nmap
    test ! -e /usr/share/nmap
    test ! -e /usr/local/bin/nmap
    test ! -e /usr/local/bin/naabu
    ! find / -xdev \( -iname "nmap" -o -iname "nmap-scripts" -o -iname "nmap-service-probes" -o -iname "naabu" \) -print -quit | grep -q .
'

echo "Native runtime passed external-scanner absence checks: $image"
