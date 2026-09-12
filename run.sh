#!/bin/bash
# 微信聊天记录导出 + 图片OCR/视觉描述 + 语音转文字
# 用法: ./run.sh <联系人昵称> [时间范围]
# 时间范围示例: 20260702-20260807 / 1d / 1w / 1m / 1y / today / yesterday

# 真实微信数据目录（main.py 本地快照 + 本地密钥解密）
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"
if [ -f "$SCRIPT_DIR/wx_secrets.env" ]; then
  . "$SCRIPT_DIR/wx_secrets.env"
fi
if [ -z "$WECHAT_BASE" ]; then
  echo "[错误] 未配置 WECHAT_BASE，请在 wx_secrets.env 中设置真实微信数据目录"
  exit 1
fi
REAL_BASE="$WECHAT_BASE"
CONTACT="${1:-${WECHAT_CONTACT:-}}"
RANGE="${2:-}"

if [ -z "$CONTACT" ]; then
  echo "用法: ./run.sh <联系人昵称> [时间范围]"
  exit 1
fi

if [ ! -d "$REAL_BASE/db_storage" ]; then
  echo "[错误] 真实微信数据目录不存在: $REAL_BASE"
  exit 1
fi

if [ -n "$RANGE" ]; then
  echo "== 导出聊天记录: $CONTACT 范围: $RANGE (本地快照解密) =="
  python3 src/main.py "$CONTACT" --range "$RANGE"
else
  echo "== 导出聊天记录: $CONTACT (本地快照解密) =="
  python3 src/main.py "$CONTACT"
fi

echo "== 输出前 100 行 =="
LATEST=$(ls -t ./chat_history_*.txt 2>/dev/null | head -n 1)
if [ -n "$LATEST" ]; then
  echo "输出文件: $LATEST"
  tail -n 100 "$LATEST"
else
  echo "未找到输出文件"
fi
