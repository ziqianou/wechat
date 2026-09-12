"""微信4.0媒体解密 + OCR + 视觉描述工具模块"""
import os
import io
import re
import sys
import struct
import subprocess
import sqlite3
import hashlib
import datetime

from Crypto.Cipher import AES

import logging_config as lc

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
from wx_secrets import IMAGE_AES_KEY

logger = lc.get_logger('media_tools')

AES_KEY = bytes.fromhex(IMAGE_AES_KEY)
XOR_KEY = 172
WXGF_HEADER = b'wxgf'

# ---------------------------------------------------------------- 解密核心
def _decrypt_aes_ecb(data, key):
    if not data:
        return b''
    n = len(data) - (len(data) % 16)
    if n <= 0:
        return b''
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted = cipher.decrypt(data[:n])
    pad = decrypted[-1]
    if pad and all(b == pad for b in decrypted[-pad:]):
        decrypted = decrypted[:-pad]
    return decrypted


def decrypt_dat_bytes(data):
    """解密 V2 dat 原始字节，返回解密后的图片字节（可能是 wxgf/jpg/png）"""
    if len(data) < 15:
        raise ValueError('too short')
    aes_len = struct.unpack_from('<I', data, 6)[0]
    xor_len = struct.unpack_from('<I', data, 10)[0]
    payload = data[15:]
    aes_len0 = (aes_len // 16 * 16) + 16
    aes_len0 = min(aes_len0, len(payload))
    if aes_len > 0 and AES_KEY:
        dec = _decrypt_aes_ecb(payload[:aes_len0], AES_KEY)
        aes_data = dec[:aes_len]
    else:
        aes_data = b''
    result = bytearray(aes_data)
    mid_start = aes_len0
    mid_end = len(payload) - xor_len
    if mid_start < mid_end:
        result += payload[mid_start:mid_end]
    if xor_len > 0 and mid_end < len(payload):
        tail = payload[mid_end:]
        result += bytes(b ^ XOR_KEY for b in tail)
    return bytes(result)


def _find_partitions(data):
    if len(data) < 5:
        raise ValueError('invalid wxgf')
    header_len = data[4]
    if header_len >= len(data):
        raise ValueError('invalid wxgf header length')
    patterns = [b'\x00\x00\x00\x01', b'\x00\x00\x01']
    for pat in patterns:
        parts = []
        max_ratio = 0.0
        max_idx = -1
        offset = 0
        while header_len + offset <= len(data):
            search_data = data[header_len + offset:]
            idx = search_data.find(pat)
            if idx < 0:
                break
            abs_idx = header_len + offset + idx
            if abs_idx < 4:
                offset += idx + 1
                continue
            length = int.from_bytes(data[abs_idx - 4:abs_idx], 'big')
            if length <= 0 or abs_idx + length > len(data):
                offset += idx + 1
                continue
            ratio = float(length) / float(len(data))
            parts.append((abs_idx, length, ratio))
            if ratio > max_ratio:
                max_ratio = ratio
                max_idx = len(parts) - 1
            offset += idx + length
        if parts:
            return {'parts': parts, 'max_ratio': max_ratio, 'max_index': max_idx}
    raise ValueError('no partition found')


def wxgf_extract_h265(data):
    """从 wxgf 中提取 H265 原始流"""
    parts = _find_partitions(data)
    best = parts['parts'][parts['max_index']]
    return data[best[0]:best[0] + best[1]]


def convert_v4(data):
    """解密 dat 并返回 (图片字节, 扩展名, 是否为wxgf, h265字节或None)"""
    logger.debug("convert_v4: 输入 %d 字节", len(data))
    raw = decrypt_dat_bytes(data)
    logger.debug("解密后 %d 字节，头部=%s", len(raw), raw[:4].hex())
    if raw[:4] == b'wxgf':
        try:
            h265 = wxgf_extract_h265(raw)
            logger.debug("wxgf 提取 h265 %d 字节", len(h265))
        except Exception as e:
            logger.warning("wxgf 分区解析失败: %s", e)
            h265 = None
        return raw, 'wxgf', True, h265
    ext_map = [(b'\xff\xd8\xff', 'jpg'), (b'\x89PNG', 'png'), (b'GIF8', 'gif'),
               (b'II*\x00', 'tiff'), (b'BM', 'bmp')]
    for sig, ext in ext_map:
        if raw.startswith(sig):
            logger.debug("识别为 %s 格式", ext)
            return raw, ext, False, None
    logger.warning("无法识别的图片格式，返回 bin")
    return raw, 'bin', False, None


def wxgf_to_jpg_bytes(h265):
    """用 ffmpeg 将 h265 单帧/视频转为 jpg 字节"""
    try:
        p = subprocess.Popen(['ffmpeg', '-i', '-', '-vframes', '1', '-c:v', 'mjpeg',
                              '-q:v', '4', '-f', 'image2', '-'],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
        out, err = p.communicate(input=h265)
        if p.returncode == 0 and out:
            logger.debug("ffmpeg 转码 h265 -> jpg 成功 (%d 字节)", len(out))
            return out
        logger.warning("ffmpeg 转码失败: %s", err.decode('utf-8', errors='ignore')[:200])
    except Exception as e:
        logger.warning("ffmpeg 调用异常: %s", e)
    return None


# ---------------------------------------------------------------- 会话定位
def locate_conversation(message_db, contact_db, contact_name):
    """按昵称定位会话表（支持私聊联系人，也支持群聊名称），返回 (table_name, username, display_name, chat_dir_hash)"""
    conn = _open_db(message_db)
    cur = conn.cursor()
    cur.execute("PRAGMA table_info(Name2Id)")
    n2id_cols = [r[1] for r in cur.fetchall()]
    has_is_session = 'is_session' in n2id_cols
    logger.debug("Name2Id 列: %s (has_is_session=%s)", n2id_cols, has_is_session)

    cc = _open_db(contact_db)
    ccur = cc.cursor()
    ccur.execute("PRAGMA table_info(Contact)")
    cols = {r[1].lower(): r[1] for r in ccur.fetchall()}
    u_col = cols.get('username', 'username')
    r_col = cols.get('remark', 'remark')
    n_col = cols.get('nick_name', cols.get('nickname', 'nick_name'))
    ccur.execute(f"SELECT {u_col}, {r_col}, {n_col} FROM Contact")
    contact_map = {}       # 私聊 display_lower -> username
    group_map = {}         # 群聊 display_lower -> username
    display_by_username = {}  # username -> 真实显示名
    excluded = 0
    for username, remark, nickname in ccur.fetchall():
        # 排除服务号（openim）；群聊单独归入 group_map
        if not username or '@openim' in username:
            excluded += 1
            continue
        display = remark.strip() if remark and remark.strip() else (
            nickname.strip() if nickname and nickname.strip() else username)
        if not display:
            continue
        display_by_username[username] = display
        if '@chatroom' in username:
            group_map[display.lower()] = username
        else:
            contact_map[display.lower()] = username
    cc.close()
    logger.debug("通讯录解析完成，排除服务号 %d 个，保留私聊 %d 个、群聊 %d 个",
                 excluded, len(contact_map), len(group_map))

    # 精确匹配昵称/备注（不区分大小写），先私聊后群聊
    target = contact_name.strip().lower()
    username = contact_map.get(target) or group_map.get(target)
    display_name = display_by_username.get(username, contact_name.strip()) if username else contact_name.strip()
    if not username:
        # 也尝试用 wxid / 群聊 id 直接匹配
        raw = contact_name.strip()
        if raw.startswith('wxid_') or raw.endswith('@chatroom'):
            username = raw
            display_name = raw
    # 模糊匹配：target 是某 display 的子串，或某 display 含 target
    if not username:
        candidates = []
        for disp_lower, uname in contact_map.items():
            if target in disp_lower:
                candidates.append((len(disp_lower), display_by_username.get(uname, uname), uname))
        for disp_lower, uname in group_map.items():
            if target in disp_lower:
                candidates.append((len(disp_lower), display_by_username.get(uname, uname), uname))
        if candidates:
            # 优先普通 wxid 联系人（排除 openim/chatroom 等服务号）
            real = [c for c in candidates if c[2].startswith('wxid_')]
            if not real:
                real = candidates
            # 取最短匹配（最精确）
            real.sort(key=lambda x: x[0])
            display_name, username = real[0][1], real[0][2]
            logger.debug("模糊匹配命中: %s -> %s (%s)", target, display_name, username)
    if not username:
        raise ValueError(f"未找到联系人/群聊: {contact_name}（可尝试输入备注名、群聊名称或 wxid/群聊id）")

    # 会话表 = Msg_ + md5(username)
    table = 'Msg_' + hashlib.md5(username.encode()).hexdigest()
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?", (table,))
    if not cur.fetchone():
        raise ValueError(f"会话表不存在: {table} (username={username})")
    conn.close()
    logger.debug("会话表确认存在: %s", table)
    return table, username, display_name, hashlib.md5(username.encode()).hexdigest()


# ---------------------------------------------------------------- 媒体定位
def _snap_db(path):
    """微信真实目录下的库先复制到本地，避免污染微信运行目录。"""
    try:
        from local_db import local_copy
        return local_copy(path)
    except Exception:
        return path


def _open_db(path):
    """打开本地快照（自动按密钥解密）。返回 sqlite3/sqlcipher3 连接。"""
    from local_db import open_local
    return open_local(_snap_db(path))


def build_image_resolver(message_db, hardlink_db, attach_root):
    """返回 (md5 -> (abs_path, thumb_path)) 解析器"""
    try:
        hl = _open_db(hardlink_db)
        hcur = hl.cursor()
        hcur.execute('SELECT rowid, username FROM dir2id')
        d2id = {r[0]: r[1] for r in hcur.fetchall()}
        resolver = {}
        for dir1, dir2, fname, md5 in hcur.execute(
                'SELECT dir1, dir2, file_name, md5 FROM image_hardlink_info_v4'):
            conv = d2id.get(dir1)
            month = d2id.get(dir2)
            if not conv or not month or not fname:
                continue
            p = os.path.join(attach_root, conv, month, 'Img', fname)
            resolver[md5] = p
        hl.close()
        return resolver
    except Exception as e:
        logger.warning("hardlink.db 打开/解密失败，跳过图片本地映射: %s", e)
        return {}


def build_conversation_images(hardlink_db, attach_root, conv_hash):
    """返回某会话(md5 hash)在本地的所有图片文件绝对路径列表。
    这些图片可能无法通过消息 md5 关联，但属于该会话目录。"""
    try:
        hl = _open_db(hardlink_db)
        hcur = hl.cursor()
        hcur.execute('SELECT rowid, username FROM dir2id')
        d2id = {r[0]: r[1] for r in hcur.fetchall()}
        conv_dir = None
        for rowid, username in d2id.items():
            if username == conv_hash:
                conv_dir = rowid
                break
        paths = []
        if conv_dir is not None:
            for dir1, dir2, fname in hcur.execute(
                    'SELECT dir1, dir2, file_name FROM image_hardlink_info_v4 WHERE dir1=?',
                    (conv_dir,)):
                month = d2id.get(dir2)
                if not month or not fname:
                    continue
                p = os.path.join(attach_root, conv_hash, month, 'Img', fname)
                if os.path.exists(p):
                    paths.append(p)
        hl.close()
        return paths
    except Exception as e:
        logger.warning("hardlink.db 打开/解密失败，跳过会话图片扫描: %s", e)
        return []


def build_voice_resolver(message_db, media_db):
    """返回 {local_id: voice_data} 和 chat_name_id 查询"""
    mconn = _open_db(media_db)
    mcur = mconn.cursor()
    mcur.execute('SELECT rowid, user_name FROM Name2Id')
    n2i = {r[1]: r[0] for r in mcur.fetchall()}
    return mconn, mcur, n2i


def get_media_chat_name_id(media_db, username):
    """从 media db 的 Name2Id 获取 username 对应的 chat_name_id"""
    if not os.path.exists(media_db):
        return None
    conn = _open_db(media_db)
    cur = conn.cursor()
    cur.execute('SELECT rowid, user_name FROM Name2Id WHERE user_name=?', (username,))
    row = cur.fetchone()
    conn.close()
    return row[0] if row else None


# ---------------------------------------------------------------- OCR / VLM（懒加载单例）
_ocr = None
_vlm = None
_vlm_proc = None


def get_ocr():
    global _ocr
    if _ocr is None:
        from rapidocr_onnxruntime import RapidOCR
        logger.info("加载 RapidOCR 模型")
        _ocr = RapidOCR()
        logger.info("RapidOCR 就绪")
    return _ocr


def ocr_image(img_bytes, suffix='jpg'):
    """OCR 图片，返回文字列表（内存处理，避免临时文件）"""
    import numpy as np
    from PIL import Image
    import io
    ocr = get_ocr()
    img = Image.open(io.BytesIO(img_bytes))
    if img.mode != 'RGB':
        img = img.convert('RGB')
    arr = np.array(img)
    res, _ = ocr(arr)
    lines = []
    if res:
        for box, text, score in res:
            if text and text.strip():
                lines.append(text.strip())
    return lines


def get_vlm():
    global _vlm, _vlm_proc
    if _vlm is None:
        # 清除 socks 代理（系统 ALL_PROXY 会导致 HF 下载失败）
        for k in ('ALL_PROXY', 'all_proxy', 'HTTP_PROXY', 'http_proxy',
                  'HTTPS_PROXY', 'https_proxy', 'NO_PROXY', 'no_proxy'):
            os.environ.pop(k, None)
        # 强制离线模式：模型已缓存，避免每次联网检查/下载
        os.environ.setdefault('HF_HUB_OFFLINE', '1')
        os.environ.setdefault('TRANSFORMERS_OFFLINE', '1')
        # 屏蔽 bitsandbytes 非对齐 kernel 警告（GTX1650 无影响）
        import warnings
        warnings.filterwarnings('ignore', module='bitsandbytes')
        import torch
        from transformers import AutoProcessor, AutoModelForImageTextToText, BitsAndBytesConfig
        bnb = BitsAndBytesConfig(load_in_4bit=True,
                                 bnb_4bit_compute_dtype=torch.float16,
                                 bnb_4bit_quant_type='nf4',
                                 llm_int8_enable_fp32_cpu_offload=True)
        _vlm_proc = AutoProcessor.from_pretrained('Qwen/Qwen2.5-VL-3B-Instruct',
                                                  trust_remote_code=True,
                                                  local_files_only=True)
        _vlm = AutoModelForImageTextToText.from_pretrained(
            'Qwen/Qwen2.5-VL-3B-Instruct', trust_remote_code=True,
            quantization_config=bnb, device_map='auto',
            max_memory={0: '3.2GiB', 'cpu': '20GiB'},
            local_files_only=True)
    return _vlm, _vlm_proc


def describe_image(img_bytes, suffix='jpg', max_side=320, prompt=None):
    """用 Qwen2.5-VL 描述图片，返回中文描述"""
    import torch
    from PIL import Image
    if prompt is None:
        prompt = '请用中文简要描述这张图片的内容。'
    model, proc = get_vlm()
    import tempfile
    with tempfile.NamedTemporaryFile(suffix='.' + suffix, delete=False) as f:
        f.write(img_bytes)
        tmp = f.name
    try:
        img = Image.open(tmp).convert('RGB')
        w, h = img.size
        s = max_side / max(w, h)
        if s < 1.0:
            img = img.resize((max(1, int(w * s)), max(1, int(h * s))))
        msg = [{'role': 'user', 'content': [{'type': 'image'}, {'type': 'text', 'text': prompt}]}]
        text = proc.apply_chat_template(msg, tokenize=False, add_generation_prompt=True)
        inputs = proc(text=text, images=img, return_tensors='pt').to('cuda')
        with torch.no_grad():
            out = model.generate(**inputs, max_new_tokens=128)
        desc = proc.batch_decode(out, skip_special_tokens=True)[0]
    finally:
        os.unlink(tmp)
    # 清理聊天模板残留标记（system/user/assistant）
    for marker in ('assistant', 'user', 'system'):
        if marker + '\n' in desc:
            desc = desc.split(marker + '\n')[-1]
        elif marker + ' ' in desc:
            desc = desc.rsplit(marker + ' ', 1)[-1]
    desc = desc.strip()
    if desc.startswith('请用中文简要描述'):
        desc = desc.replace('请用中文简要描述这张图片的内容。', '').strip()
    return desc
