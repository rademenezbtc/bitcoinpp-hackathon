#!/bin/sh
# Stand-in for frostsnap_sp_bridge (rehearsals without hardware).
# Device/share via MOCK_DEVICE / MOCK_SHARE env vars.
exec bun "$(dirname "$0")/mock-bridge.ts" "$@"
