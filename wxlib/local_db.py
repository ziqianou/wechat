"""微信数据库本地快照工具

任何需要访问微信真实目录（xwechat_files）下数据库的脚本，都应先通过
`local_copy()` 把目标库（连同 -wal/-shm）复制到本地工作目录，再连接本地副本。
避免在微信运行目录上创建/修改 -shm、-wal 等文件，防止污染微信数据。

用法:
    from local_db import local_copy
    path = local_copy('/home/.../xwechat_files/.../db_storage/sns/sns.db')
    # 之后用 path 连接（SQLCipher 密钥逻辑不变）
"""
import os
import sys
import time
import shutil
import hashlib

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
from wx_secrets import DB_KEYS

LOCAL_ROOT = os.path.join(_ROOT, 'data', 'db_local')
MARKER_EXT = '.snapshot.json'

_cache = {}
_cache_mtime = {}


def _is_wechat_path(path):
    return os.path.sep + 'xwechat_files' + os.path.sep in path


def _stable_name(real_path):
    """在本地生成与真实库一一对应的稳定文件名。"""
    h = hashlib.md5(real_path.encode()).hexdigest()[:16]
    base = os.path.basename(real_path)
    return f"{h}_{base}"


def original_basename(local_path):
    """从本地快照文件名还原原始库基准名（如 xxx_sns.db -> sns.db）。"""
    name = os.path.basename(local_path)
    if '_' in name:
        return name.split('_', 1)[1]
    return name


def key_for(local_path):
    """按本地快照路径查派生密钥；非加密库返回 None。"""
    return DB_KEYS.get(original_basename(local_path))


def local_copy(real_path):
    """把真实微信库复制到本地，返回本地路径。非微信路径原样返回。

    复制主文件 + 关联的 -wal / -shm（若存在），保证本地副本数据完整。
    已复制过且源文件未变化时直接复用（避免重复拷贝大文件）。"""
    if not _is_wechat_path(real_path):
        return real_path
    os.makedirs(LOCAL_ROOT, exist_ok=True)
    local = os.path.join(LOCAL_ROOT, _stable_name(real_path))

    def _mtime_size(p):
        if not os.path.exists(p):
            return None
        st = os.stat(p)
        return (st.st_mtime, st.st_size)

    changed = False
    for suffix in ('', '-wal', '-shm'):
        src = real_path + suffix
        dst = local + suffix
        key = suffix or '_main'
        if not os.path.exists(src):
            continue
        sm = _mtime_size(src)
        if _cache_mtime.get((real_path, key)) != sm or not os.path.exists(dst):
            try:
                shutil.copy2(src, dst)
            except (PermissionError, OSError):
                # 无法复制元数据（属主/权限受限）时降级为仅复制内容
                shutil.copy(src, dst)
            _cache_mtime[(real_path, key)] = sm
            changed = True
    return local


def clear_local():
    """清空本地快照目录（释放磁盘空间）。"""
    if os.path.isdir(LOCAL_ROOT):
        shutil.rmtree(LOCAL_ROOT, ignore_errors=True)
        os.makedirs(LOCAL_ROOT, exist_ok=True)


def open_local(local_path, read_only=True):
    """打开本地快照的 SQLCipher 连接（自动解密）。返回 sqlite3.Connection 或 None。
    非加密库用标准 sqlite3；加密库用 sqlcipher3 + 对应密钥。"""
    key = key_for(local_path)
    if key:
        import sqlcipher3
        conn = sqlcipher3.connect(local_path)
        conn.execute(f"PRAGMA key = \"x'{key}'\";")
        return conn
    import sqlite3
    return sqlite3.connect(local_path)


def open_db(real_path):
    """从微信真实路径打开数据库连接：先本地快照，再按密钥解密。"""
    return open_local(local_copy(real_path))


if __name__ == '__main__':
    import sys
    for p in sys.argv[1:]:
        print(local_copy(p))
