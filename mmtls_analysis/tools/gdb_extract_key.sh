#!/bin/bash
# WeChat mmtls AES-128-GCM key + IV extraction via gdb hardware breakpoints.
# SAFE: hardware breakpoints (DR registers) don't modify code bytes.
#
# Usage: sudo bash gdb_extract_key.sh
#   - breaks at the mmtls cipher op (0x6fa9010), reads key (cobj+0x50) + IV (cobj+0x30)
#   - requires a WeChat message send while it runs
if [ "$(id -u)" -ne 0 ]; then
  echo "[错误] 需要 root 权限运行：sudo bash $0" >&2
  exit 1
fi

PID=$(pgrep -x wechat | head -1)
[ -z "$PID" ] && { echo "wechat not running"; exit 1; }
BASE=$(awk '$3=="00000000" && $4=="08:13" {print $1}' /proc/$PID/maps | cut -d- -f1 | head -1)
TARGET=$(python3 -c "print(hex(int('$BASE',16)+0x6fa9010))")
echo "[*] PID=$PID BASE=$BASE TARGET=$TARGET"
echo "[*] send a WeChat message now..."
cat > /tmp/opencode/gdb_extract_key.gdb <<EOF
set pagination off
set confirm off
set auto-solib-add off
hbreak *$TARGET
continue
set \$cobj = *(void**)(\$rdi+8)
set \$key = *(void**)(\$cobj+0x50)
set \$iv  = *(void**)(\$cobj+0x30)
dump binary memory /tmp/opencode/extract_key.bin  \$key \$key+0x10
dump binary memory /tmp/opencode/extract_iv.bin   \$iv  \$iv+0x0c
detach
quit
EOF
gdb -q -p $PID -nx -x /tmp/opencode/gdb_extract_key.gdb
echo "[*] key: $(xxd -p /tmp/opencode/extract_key.bin 2>/dev/null)"
echo "[*] iv : $(xxd -p /tmp/opencode/extract_iv.bin 2>/dev/null)"
