#!/bin/bash
# 捕获微信 mmtls 明文，聚焦 SNS/图片 相关请求（含 mars 路径和 body）
# 循环捕获多次，过滤含 sns/img/图片 特征的明文
if [ "$(id -u)" -ne 0 ]; then
  echo "[错误] 需要 root 权限运行：sudo bash $0" >&2
  exit 1
fi

PID=$(pgrep -x wechat | head -1)
[ -z "$PID" ] && { echo "wechat not running"; exit 1; }
BASE=$(awk '$3=="00000000" && $4=="08:13" {print $1}' /proc/$PID/maps | cut -d- -f1 | head -1)
TARGET=$(python3 -c "print(hex(int('$BASE',16)+0x6fc5960))")
OUT=/tmp/opencode/mmtls_plaintext.log
: > $OUT
echo "[*] PID=$PID TARGET=$TARGET 捕获 mmtls 明文 (Ctrl+C 结束)"
for i in $(seq 1 50); do
  timeout 4 gdb -q -p $PID -nx -batch \
    -ex 'set pagination off' \
    -ex "hbreak *$TARGET if \$rdx==0x17" \
    -ex 'continue' \
    -ex 'printf "\n===HIT===\n"' \
    -ex 'set $plen = *(unsigned int*)$r8' \
    -ex 'printf "body_len=%u\n", $plen' \
    -ex 'x/96bx $r8' \
    -ex 'detach' \
    -ex 'quit' 2>&1 | grep -A4 '===HIT===' >> $OUT
done
echo "捕获完成，查看 $OUT"
