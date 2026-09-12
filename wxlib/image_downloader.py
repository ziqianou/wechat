"""微信缺失图片下载工具

- V2 dat 生成（已验证算法）：明文图片 -> V2 dat
- 表情包/emoji：XML 自带 cdnurl，直接下载
- 普通 C2C 图片：需 storeid URL（gdb 捕获或微信下载）
- 落盘到真实 attach 目录 + 更新 hardlink 数据库

所有数据库直接解密真实目录（绕开 /app/data 云备份）。
"""
import os
import re
import sys
import struct
import sqlite3
import hashlib
import logging
import urllib.request
import urllib.error
import zstandard as zstd

from Crypto.Cipher import AES

import logging_config as lc

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
from wx_secrets import WX_BASE, SELF_WXID, DB_KEYS, IMAGE_AES_KEY

logger = lc.get_logger('image_downloader')

# ---------------- 路径与密钥 ----------------
DB_MESSAGE = os.path.join(WX_BASE, 'db_storage/message/message_0.db')
DB_HARDLINK = os.path.join(WX_BASE, 'db_storage/hardlink/hardlink.db')
ATTACH_ROOT = os.path.join(WX_BASE, 'msg/attach')

# V2 dat 常量（与 media_tools.py 一致）
V2_AES_KEY = bytes.fromhex(IMAGE_AES_KEY)
V2_HEADER = b'\x07\x08\x56\x32\x08\x07'
V2_AES_LEN = 1024
V2_XOR = 0xAC

CACHE_DIR = os.path.join(_ROOT, 'data', 'cache', 'downloads')
os.makedirs(CACHE_DIR, exist_ok=True)


# ---------------- 数据库访问 ----------------
def open_db(db_path, key_hex):
    import sqlcipher3 as sqlite3
    conn = sqlite3.connect(_snap_db(db_path))
    conn.execute(f"PRAGMA key = \"x'{key_hex}'\";")
    return conn


def _snap_db(path):
    """微信真实目录下的库先复制到本地，避免污染微信运行目录。"""
    try:
        from local_db import local_copy
        return local_copy(path)
    except Exception:
        return path


def get_message_db():
    return open_db(DB_MESSAGE, DB_KEYS['message_0.db'])


def get_hardlink_db():
    return open_db(DB_HARDLINK, DB_KEYS['hardlink.db'])


# ---------------- V2 dat 生成 ----------------
def img_to_v2dat(img_bytes):
    """明文图片字节 -> V2 dat 格式（已验证与微信原生一致，可逆）"""
    head_len = V2_AES_LEN
    plain_head = img_bytes[:head_len]
    # 不足 16 对齐补齐（微信同款处理）
    pad = (16 - len(plain_head) % 16) % 16
    if pad:
        plain_head = plain_head + b'\x00' * pad
    aes_enc = AES.new(V2_AES_KEY, AES.MODE_ECB).encrypt(plain_head)
    xor_part = bytes(b ^ V2_XOR for b in img_bytes[head_len:])
    payload = aes_enc + xor_part
    aes_len = head_len
    xor_len = len(img_bytes) - head_len
    header = V2_HEADER + struct.pack('<II', aes_len, xor_len) + b'\x00'
    return header + payload


def v2dat_to_img(dat_bytes):
    """V2 dat -> 明文图片字节（逆向，验证用）"""
    import io
    aes_len = struct.unpack_from('<I', dat_bytes, 6)[0]
    xor_len = struct.unpack_from('<I', dat_bytes, 10)[0]
    payload = dat_bytes[15:]
    aes0 = (aes_len // 16 * 16) + 16
    aes0 = min(aes0, len(payload))
    if aes_len > 0:
        dec = AES.new(V2_AES_KEY, AES.MODE_ECB).decrypt(payload[:aes0])
        result = bytearray(dec[:aes_len])
    else:
        result = bytearray()
    mid_end = len(payload) - xor_len
    if aes0 < mid_end:
        result += payload[aes0:mid_end]
    if xor_len > 0 and mid_end < len(payload):
        result += bytes(b ^ V2_XOR for b in payload[mid_end:])
    return bytes(result)


# ---------------- 消息内容解码 ----------------
def decode_content(data):
    if isinstance(data, bytes):
        if data.startswith(b'\x28\xb5\x2f\xfd'):
            try:
                return zstd.ZstdDecompressor().decompress(data).decode('utf-8', errors='ignore')
            except Exception:
                return data.decode('utf-8', errors='ignore')
        return data.decode('utf-8', errors='ignore')
    return str(data)


def extract_conv_messages(conv_hash, table_name=None):
    """提取指定会话所有消息的 (local_id, create_time, content, raw)"""
    conn = get_message_db()
    cur = conn.cursor()
    if table_name is None:
        table_name = 'Msg_' + conv_hash
    try:
        cur.execute(f"SELECT local_id, create_time, message_content, compress_content FROM {table_name} ORDER BY create_time")
        rows = cur.fetchall()
    except Exception as e:
        logger.error("读取消息表失败 %s: %s", table_name, e)
        rows = []
    conn.close()
    out = []
    for lid, ct, mc, cc in rows:
        c = mc if mc is not None else cc
        t = decode_content(c)
        out.append({'local_id': lid, 'create_time': ct, 'content': t})
    return out


# ---------------- 图片信息提取 ----------------
def extract_images_from_content(content):
    """从消息 XML 提取图片信息列表:
    [{'type': 'emoji'|'img', 'md5':..., 'url':..., 'aeskey':..., 'fileid_der':..., 'length':...}]
    """
    images = []
    # emoji: 自带 cdnurl
    for m in re.finditer(r'<emoji[^>]*>', content):
        tag = m.group(0)
        md5 = re.search(r'md5\s*=\s*"([0-9a-f]{32})"', tag)
        cdn = re.search(r'cdnurl\s*=\s*"([^"]+)"', tag)
        if md5 and cdn:
            images.append({
                'type': 'emoji',
                'md5': md5.group(1),
                'url': cdn.group(1).replace('&amp;', '&'),
            })
    # img: 需 fileid
    for m in re.finditer(r'<img\s+([^>]*)>', content):
        attrs = m.group(1)
        md5 = re.search(r'md5="([0-9a-f]{32})"', attrs)
        if not md5:
            continue
        aeskey = re.search(r'aeskey="([0-9a-f]{32})"', attrs)
        mid = re.search(r'cdnmidimgurl="([0-9a-f]+)"', attrs)
        big = re.search(r'cdnbigimgurl="([0-9a-f]+)"', attrs)
        length = re.search(r'length="(\d+)"', attrs)
        images.append({
            'type': 'img',
            'md5': md5.group(1),
            'aeskey': aeskey.group(1) if aeskey else None,
            'fileid_der': (big or mid).group(1) if (big or mid) else None,
            'length': int(length.group(1)) if length else None,
        })
    return images


# ---------------- 落盘 ----------------
def save_to_attach(conv_hash, md5, dat_bytes):
    """保存 V2 dat 到 attach 目录。返回路径或 None"""
    # 从 create_time 推断月份（由调用方提供），这里用当前月兜底
    import datetime
    month = datetime.date.today().strftime('%Y-%m')
    conv_dir = os.path.join(ATTACH_ROOT, conv_hash, month, 'Img')
    os.makedirs(conv_dir, exist_ok=True)
    fname = md5 + '.dat'
    path = os.path.join(conv_dir, fname)
    with open(path, 'wb') as f:
        f.write(dat_bytes)
    return path


def add_hardlink_record(conv_hash, md5, file_name, file_size):
    """向 hardlink.db 的 image_hardlink_info_v4 插入记录"""
    conn = get_hardlink_db()
    cur = conn.cursor()
    # 获取 dir1(dir2) rowid
    cur.execute("SELECT rowid, username FROM dir2id")
    d2id = {r[1]: r[0] for r in cur.fetchall()}
    dir1 = d2id.get(conv_hash)
    if dir1 is None:
        logger.error("会话 %s 不在 dir2id 中", conv_hash)
        conn.close()
        return False
    # dir2 用当前月
    import datetime
    month = datetime.date.today().strftime('%Y-%m')
    dir2 = d2id.get(month)
    if dir2 is None:
        # 插入月份 dir
        cur.execute("INSERT INTO dir2id(username) VALUES (?)", (month,))
        dir2 = cur.lastrowid
    md5_hash = hashlib.md5(md5.encode()).hexdigest()
    md5_hash_i = int(md5_hash, 16) % (2**63)
    try:
        cur.execute("SELECT COALESCE(MAX(_rowid_), 0) FROM image_hardlink_info_v4")
        next_rowid = cur.fetchone()[0] + 1
        cur.execute(
            "INSERT INTO image_hardlink_info_v4(md5_hash, md5, type, file_name, file_size, modify_time, dir1, dir2, _rowid_, extra_buffer) "
            "VALUES (?,?,?,?,?,?,?,?,?,?)",
            (md5_hash_i, md5, 2, file_name, file_size, int(__import__('time').time()), dir1, dir2,
             next_rowid, None))
        conn.commit()
        logger.info("hardlink 记录已添加: %s", md5)
        conn.close()
        return True
    except Exception as e:
        logger.error("hardlink 插入失败: %s", e)
        conn.close()
        return False


# ---------------- 下载 ----------------
UA = 'MicroMessenger Client'


def download_url(url, timeout=20):
    """下载 URL，返回字节或 None"""
    try:
        req = urllib.request.Request(url, headers={'User-Agent': UA})
        resp = urllib.request.urlopen(req, timeout=timeout)
        return resp.read()
    except urllib.error.HTTPError as e:
        logger.warning("下载失败 %s: HTTP %s", url[:80], e.code)
        return None
    except Exception as e:
        logger.warning("下载失败 %s: %s", url[:80], e)
        return None


# ---------------- 表情包下载（已确认可行） ----------------
def download_emoji_images(conv_hash):
    """下载会话中所有 emoji 图片，转 V2 dat 落盘。返回 (成功, 失败)"""
    messages = extract_conv_messages(conv_hash)
    emoji_images = []
    for msg in messages:
        for img in extract_images_from_content(msg['content']):
            if img['type'] == 'emoji' and img['url']:
                emoji_images.append((img, msg['create_time']))

    # 去重
    seen = set()
    ok = fail = 0
    for img, ct in emoji_images:
        md5 = img['md5']
        if md5 in seen:
            continue
        seen.add(md5)
        # 检查本地是否已有
        if _local_exists(conv_hash, md5):
            logger.debug("emoji %s 已存在本地", md5)
            continue
        data = download_url(img['url'])
        if not data:
            fail += 1
            continue
        # emoji 下载的是明文图片（PNG/JPEG）
        if _is_encrypted(data):
            logger.warning("emoji %s 返回加密数据，跳过", md5)
            fail += 1
            continue
        dat = img_to_v2dat(data)
        path = save_to_attach(conv_hash, md5, dat)
        if path:
            add_hardlink_record(conv_hash, md5, os.path.basename(path), len(dat))
            ok += 1
            logger.info("emoji %s 已下载并转 V2 dat (%dB)", md5, len(dat))
        else:
            fail += 1
    logger.info("emoji 下载完成: 成功 %d, 失败 %d", ok, fail)
    return ok, fail


def _local_exists(conv_hash, md5):
    """检查本地 attach 是否已有该 md5 的图片"""
    import glob
    conv_dir = os.path.join(ATTACH_ROOT, conv_hash)
    for f in glob.glob(os.path.join(conv_dir, '*', 'Img', md5 + '.dat')):
        if os.path.exists(f):
            return True
    # 也检查 hardlink
    conn = get_hardlink_db()
    cur = conn.cursor()
    cur.execute("SELECT 1 FROM image_hardlink_info_v4 WHERE md5=?", (md5,))
    found = cur.fetchone() is not None
    conn.close()
    return found


def _is_encrypted(data):
    """判断下载数据是否加密（非图片格式）"""
    if data[:3] == b'\xff\xd8\xff' or data[:4] == b'\x89PNG' or data[:4] == b'GIF8' or data[:4] == b'wxgf':
        return False
    return True


if __name__ == '__main__':
    lc.setup_logging(level='DEBUG')
    if len(sys.argv) < 2:
        print('用法: python3 image_downloader.py <会话 hash>')
        sys.exit(1)
    logger.info("=== 图片下载工具 ===")
    ok, fail = download_emoji_images(sys.argv[1])
    print(f"emoji 下载: 成功 {ok}, 失败 {fail}")
