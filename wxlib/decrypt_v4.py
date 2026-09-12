import struct, os, subprocess, sqlite3, sys
from Crypto.Cipher import AES

import logging_config as lc

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
from wx_secrets import IMAGE_AES_KEY

logger = lc.get_logger('decrypt_v4')

AES_KEY = bytes.fromhex(IMAGE_AES_KEY)
XOR_KEY = 172
WXGF_HEADER = b'wxgf'
MIN_RATIO = 0.6

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

def _run_ffmpeg(cmd, input_bytes):
    p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, shell=False)
    out, err = p.communicate(input=input_bytes)
    if p.returncode != 0:
        raise RuntimeError('ffmpeg failed: ' + (err[:200].decode('ignore') if err else ''))
    if not out:
        raise RuntimeError('ffmpeg output is empty')
    return out

def wxam2pic(data):
    if len(data) < 15 or not data.startswith(WXGF_HEADER):
        raise ValueError('invalid wxgf')
    parts = _find_partitions(data)
    offset, size, _ = parts['parts'][parts['max_index']]
    h265 = data[offset:offset + size]
    try:
        jpg = _run_ffmpeg(['ffmpeg', '-i', '-', '-vframes', '1', '-c:v', 'mjpeg',
                           '-q:v', '4', '-f', 'image2', '-'], h265)
        return jpg, 'jpg'
    except Exception:
        return h265, 'h265'

def _decrypt_aes_ecb(data, key):
    if len(data) % 16 != 0:
        raise ValueError('Data length must be multiple of 16')
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted = cipher.decrypt(data)
    pad = decrypted[-1]
    if pad and all(b == pad for b in decrypted[-pad:]):
        decrypted = decrypted[:-pad]
    return decrypted

def convert_v4(data):
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
    result_bytes = bytes(result)
    if result_bytes.startswith(WXGF_HEADER):
        try:
            img, ext = wxam2pic(result_bytes)
        except Exception:
            return result_bytes, 'wxgf'
        return img, ext
    # detect standard image ext
    ext_map = [(b'\xff\xd8\xff', 'jpg'), (b'\x89PNG', 'png'), (b'GIF8', 'gif'),
               (b'II*\x00', 'tiff'), (b'BM', 'bmp')]
    for sig, ext in ext_map:
        if result_bytes.startswith(sig):
            return result_bytes, ext
    return result_bytes, 'bin'

def convert_file(input_path, output_path):
    with open(input_path, 'rb') as f:
        data = f.read()
    img, ext = convert_v4(data)
    out = output_path + '.' + ext if not output_path.endswith(ext) else output_path
    with open(out, 'wb') as f:
        f.write(img)
    return out

if __name__ == '__main__':
    import glob
    if len(sys.argv) < 2:
        print('用法: python3 decrypt_v4.py <会话 attach 目录> [输出目录]')
        sys.exit(1)
    src_root = sys.argv[1]
    out_root = sys.argv[2] if len(sys.argv) > 2 else os.path.join(_ROOT, 'data', 'out')
    files = sorted(glob.glob(os.path.join(src_root, '2026-*/Img/*.dat')))
    logger.info('找到 dat 文件 %d 个', len(files))
    ok = fail = 0
    for f in files:
        rel = os.path.relpath(f, src_root)
        out = os.path.join(out_root, rel)
        os.makedirs(os.path.dirname(out), exist_ok=True)
        try:
            conv = convert_file(f, out)
            ok += 1
            logger.debug('转换成功: %s -> %s', rel, conv)
        except Exception as e:
            fail += 1
            logger.warning('转换失败: %s: %s', rel, e)
    logger.info('完成: 成功 %d 失败 %d', ok, fail)
