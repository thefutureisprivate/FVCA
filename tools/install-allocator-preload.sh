#!/usr/bin/bash
set -euo pipefail

source "$SRCDIR/tools/allocator-source.env"
test -f "$BUILDROOT$allocator_library"

# Image construction tools use the worker's allocator and mapping limits.
# Write the runtime loader policy after post-installation scripts finish.
printf '%s\n' "$allocator_library" > "$BUILDROOT/etc/ld.so.preload"
chmod 0644 "$BUILDROOT/etc/ld.so.preload"
