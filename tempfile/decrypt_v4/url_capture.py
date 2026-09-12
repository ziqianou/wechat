"""轮询扫描微信内存中的 CDN storeid URL，捕获下载 URL。

原理：微信下载图片时会生成带 storeid 的完整 URL（vweixinf/wxapp.tc.qq.com）。
通过持续扫描微信进程内存，捕获新出现的 URL 及其关联 md5。
"""
import os
import re
import time
import json
import logging
import urllib.request

import logging_config as lc

logger = lc.get_logger('url_capture')

PID = 4767
CACHE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'cache', 'downloads', 'captured_urls.json')
os.makedirs(os.path.dirname(CACHE), exist_ok=True)

# URL 正则：stodownload 且带 m= 和 filekey=
URL_RE = re.compile(
    rb'https?://(?:[a-z0-9\-]+\.)+qq\.com/[0-9]+/2040[0-9]/stodownload\?[^\x00]{80,600}'
)
MD5_RE = re.compile(rb'm=([0-9a-f]{32})')
FILEKEY_RE = re.compile(rb'filekey=([0-9a-f]+)')


def scan_memory(target_md5s=None):
    """扫描微信内存，返回 {(md5, url)} 集合"""
    if not os.path.exists(f'/proc/{PID}/mem'):
        logger.error("微信进程 %s 不存在", PID)
        return {}
    mem = open(f'/proc/{PID}/mem', 'rb', buffering=0)
    maps = open(f'/proc/{PID}/maps').read()
    found = {}
    for line in maps.splitlines():
        parts = line.split()
        if len(parts) < 2 or 'r' not in parts[1]:
            continue
        start, end = [int(x, 16) for x in parts[0].split('-')]
        size = end - start
        if size > 60 * 1024 * 1024:
            continue
        try:
            mem.seek(start)
            data = mem.read(size)
            for m in URL_RE.finditer(data):
                u = m.group(0)
                mm = MD5_RE.search(u)
                if not mm:
                    continue
                md5 = mm.group(1).decode()
                if target_md5s is not None and md5 not in target_md5s:
                    continue
                url = u.decode('utf-8', errors='ignore')
                found.setdefault(md5, url)
        except Exception:
            pass
    mem.close()
    return found


def load_cached():
    if os.path.exists(CACHE):
        try:
            with open(CACHE) as f:
                return json.load(f)
        except Exception:
            return {}
    return {}


def save_cached(data):
    with open(CACHE, 'w') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def monitor(target_md5s, duration=120, interval=2, on_capture=None):
    """监控微信内存中目标 md5 的 URL。duration 秒内轮询。"""
    target_set = set(target_md5s)
    cached = load_cached()
    captured = {}
    deadline = time.time() + duration
    logger.info("监控开始: %d 个目标 md5, 时长 %ds", len(target_set), duration)
    while time.time() < deadline:
        found = scan_memory(target_set)
        new = {md5: url for md5, url in found.items() if md5 not in cached and md5 not in captured}
        for md5, url in new.items():
            captured[md5] = url
            logger.info("捕获 URL: %s -> %s", md5, url[:90])
            if on_capture:
                on_capture(md5, url)
        if captured:
            all_data = dict(cached)
            all_data.update(captured)
            save_cached(all_data)
        time.sleep(interval)
    # 合并保存
    all_data = dict(cached)
    all_data.update(captured)
    save_cached(all_data)
    logger.info("监控结束: 捕获 %d 个新 URL", len(captured))
    return captured


if __name__ == '__main__':
    lc.setup_logging(level='INFO')
    cached = load_cached()
    print(f"已缓存 URL: {len(cached)}")
    for md5, url in list(cached.items())[:3]:
        print(f"  {md5}: {url[:100]}")
