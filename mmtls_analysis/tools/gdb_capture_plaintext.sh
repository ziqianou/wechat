#!/bin/bash
# WeChat mmtls app-data PLAINTEXT capture via gdb hardware breakpoints.
# SAFE: hardware breakpoints (DR registers) don't modify any code byte,
# unlike frida inline hooks which crash WeChat (5 SIGSEGV@0 incidents).
#
# Usage: sudo bash gdb_capture_plaintext.sh
#   - attaches to wechat, breaks at the app-data encrypt entry (0x6fc5960)
#   - dumps r8 = plaintext (mars request body) when record type == 0x17
#   - prints a readable hexdump of up to 256 bytes, then detaches cleanly
#
# Requires: you send a message / trigger WeChat traffic while it runs.
if [ "$(id -u)" -ne 0 ]; then
  echo "[错误] 需要 root 权限运行：sudo bash $0" >&2
  exit 1
fi

PID=$(pgrep -x wechat | head -1)
if [ -z "$PID" ]; then echo "wechat not running"; exit 1; fi
BASE=$(awk '$3=="00000000" && $4=="08:13" {print $1}' /proc/$PID/maps | cut -d- -f1 | head -1)
# 0x6fc5960 = mmtls record encrypt/pack entry (app-data path, called with type 0x17)
TARGET=$(python3 -c "print(hex(int('$BASE',16)+0x6fc5960))")
echo "[*] PID=$PID BASE=$BASE TARGET=$TARGET"
echo "[*] send a WeChat message now (or wait for heartbeat)..."

cat > /tmp/opencode/gdb_capture.gdb <<EOF
set pagination off
set confirm off
set auto-solib-add off
hbreak *$TARGET if \$rdx==0x17
continue
printf "\n=== mmtls APP-DATA ENCRYPT (%#x) ===\n", $TARGET
printf "ctx=%p type=%ld len=%p\n", \$rsi, \$rdx, \$r9
printf "plaintext (r8, up to 256 bytes):\n"
x/256bx \$r8
printf "\nplaintext ASCII:\n"
x/128cb \$r8
detach
quit
EOF
gdb -q -p $PID -nx -x /tmp/opencode/gdb_capture.gdb
