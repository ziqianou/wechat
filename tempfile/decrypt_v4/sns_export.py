"""导出微信朋友圈(SNS)缓存图片（按原图/缩略图分类）

将微信 cache/<月份>/Sns/Img/<hash>/<文件名> 下的加密图片(V2 dat)解密，
按图片尺寸区分 原图/缩略图，输出到：
    tempfile/sns_images/<月份>/Sns/Img/原图/<文件名>.jpg
    tempfile/sns_images/<月份>/Sns/Img/缩略图/<文件名>.jpg

判断标准：图片 max(宽,高) >= 500px 为原图，否则为缩略图。
Video/Temp 目录原样保留。
"""
import os
import sys
import glob
import logging

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
from wx_secrets import WX_BASE
import media_tools as mt
import logging_config as lc

logger = lc.get_logger('sns_export')

CACHE_ROOT = os.path.join(WX_BASE, 'cache')
OUT_ROOT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'sns_images')

ORIGINAL_THRESHOLD = 500  # max(宽,高) >= 500 视为原图
CATEGORIES = ('原图', '缩略图')
SNS_SUBDIRS = ('Img', 'Video', 'Temp')


def classify_size(w, h):
    """按尺寸分类：'原图' 或 '缩略图'"""
    return '原图' if max(w, h) >= ORIGINAL_THRESHOLD else '缩略图'


def get_size(img_bytes, ext):
    """读取图片尺寸 (w, h)"""
    from PIL import Image
    import io
    try:
        pil = Image.open(io.BytesIO(img_bytes))
        return pil.size
    except Exception:
        return None


def export_sns_raw(months=None):
    """按原图/缩略图分类导出 SNS 缓存。months: ['2026-08', ...] 或 None(全部)"""
    os.makedirs(OUT_ROOT, exist_ok=True)
    if months is None:
        months = sorted(set(os.path.basename(d) for d in glob.glob(os.path.join(CACHE_ROOT, '*'))))

    exported = {'原图': 0, '缩略图': 0}
    failed = 0
    other = 0

    for month in months:
        sns_root = os.path.join(CACHE_ROOT, month, 'Sns')
        if not os.path.isdir(sns_root):
            logger.debug("跳过 %s（无 Sns）", month)
            continue

        for sub in SNS_SUBDIRS:
            sub_dir = os.path.join(sns_root, sub)
            if not os.path.isdir(sub_dir):
                continue
            for root, dirs, files in os.walk(sub_dir):
                for fname in sorted(files):
                    src = os.path.join(root, fname)
                    rel = os.path.relpath(src, sns_root)  # e.g. Img/79/24c4...
                    rel_parts = rel.split(os.sep)          # ['Img','79','24c4...']

                    try:
                        data = open(src, 'rb').read()
                        img, ext, wxgf, h265 = mt.convert_v4(data)
                        if ext not in ('jpg', 'png', 'gif', 'bmp', 'tiff'):
                            ext = 'jpg'
                    except Exception as e:
                        logger.warning("解密失败 %s: %s", rel, e)
                        failed += 1
                        continue

                    out_name = os.path.basename(fname) + '.' + ext

                    # Img：按原图/缩略图分类，去掉两位 hash 层
                    if sub == 'Img':
                        size = get_size(img, ext)
                        if size is None:
                            cat = '缩略图'  # 无法读取尺寸，归为缩略图
                        else:
                            cat = classify_size(*size)
                        out_dir = os.path.join(OUT_ROOT, month, 'Sns', 'Img', cat)
                        exported[cat] += 1
                    else:
                        # Video/Temp：保留原结构（hash 子目录）
                        out_dir = os.path.join(OUT_ROOT, month, 'Sns', sub,
                                               *rel_parts[1:-1])  # 保留 hash 层
                        other += 1

                    os.makedirs(out_dir, exist_ok=True)
                    out_path = os.path.join(out_dir, out_name)
                    try:
                        with open(out_path, 'wb') as out:
                            out.write(img)
                    except Exception as e:
                        logger.warning("写入失败 %s: %s", out_path, e)
                        failed += 1

    logger.info("完成: 原图 %d, 缩略图 %d, 其他 %d, 失败 %d",
                exported['原图'], exported['缩略图'], other, failed)
    return exported


if __name__ == '__main__':
    lc.setup_logging(level='INFO')
    export_sns_raw()
