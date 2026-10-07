#!/bin/bash
# Lance l'application sur Mac (Intel ou Apple Silicon) depuis la clÃ© USB.
cd "$(dirname "$0")" || exit 1
case "$(uname -m)" in
  arm64) BIN=./Participants-mac-arm64 ;;
  *)     BIN=./Participants-mac-intel ;;
esac
xattr -dr com.apple.quarantine . 2>/dev/null
chmod +x "$BIN" 2>/dev/null
exec "$BIN"
