#!/usr/bin/env python3
"""微信 4.0 文件消息导出：关联聊天记录与 msg/file 中的具体文件。

原理:
1. 遍历 message_0/message_1 所有 Msg_* 表，解压 zstd message_content，找 appmsg type=6 文件消息
   （title=文件名、md5、attachid）
2. 从 hardlink.db 的 file_hardlink_info_v4 按 md5 关联磁盘文件名（可能带 (1)(2) 后缀）
3. 经 Name2Id + Contact 表解析出文件来自哪个会话/联系人
4. 输出 CSV：消息时间、发送者、文件名、磁盘路径、大小

所有数据库一律本地快照 + SQLCipher 解密，不污染微信目录。
"""
import os
import re
import sys
import html
import sqlite3
import hashlib
import datetime
import argparse
import zstandard as zstd

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'tempfile', 'decrypt_v4'))
import logging_config as lc
from local_db import local_copy, key_for
from wx_secrets import WX_BASE, SELF_WXID

logger = lc.get_logger('export_files')

DB_MESSAGE_0 = os.path.join(WX_BASE, 'db_storage/message/message_0.db')
DB_MESSAGE_1 = os.path.join(WX_BASE, 'db_storage/message/message_1.db')
DB_HARDLINK = os.path.join(WX_BASE, 'db_storage/hardlink/hardlink.db')
DB_CONTACT = os.path.join(WX_BASE, 'db_storage/contact/contact.db')
FILE_ROOT = os.path.join(WX_BASE, 'msg', 'file')


def open_db(path):
    local = local_copy(path)
    key = key_for(local)
    if key:
        import sqlcipher3
        conn = sqlcipher3.connect(local)
        conn.execute(f"PRAGMA key = \"x'{key}'\";")
        return conn
    return sqlite3.connect(local)


def load_name2id(conn):
    """Name2Id: rowid -> username；以及 表名hash -> username"""
    cur = conn.cursor()
    cur.execute("SELECT rowid, user_name FROM Name2Id")
    n2id = {}
    h2name = {}
    for rid, uname in cur.fetchall():
        n2id[str(rid)] = uname
        h2name[hashlib.md5(uname.encode()).hexdigest()] = uname
    return n2id, h2name


def load_contact(conn):
    """wxid -> 显示名（备注 > 昵称 > wxid）"""
    cur = conn.cursor()
    cur.execute("PRAGMA table_info(Contact)")
    cols = {r[1].lower(): r[1] for r in cur.fetchall()}
    u_col = cols.get('username', 'username')
    r_col = cols.get('remark', 'remark')
    n_col = cols.get('nick_name', cols.get('nickname', 'nick_name'))
    cur.execute(f"SELECT {u_col}, {r_col}, {n_col} FROM Contact")
    contact = {}
    for username, remark, nickname in cur.fetchall():
        if not username:
            continue
        display = (remark or '').strip() or (nickname or '').strip() or username
        contact[username] = display
    return contact


def load_file_map(conn):
    """md5 -> {name(磁盘名), size, dir1, dir2}"""
    cur = conn.cursor()
    cur.execute("SELECT rowid, username FROM dir2id")
    d2id = {r[0]: r[1] for r in cur.fetchall()}
    cur.execute("SELECT md5, file_name, file_size, dir1, dir2 FROM file_hardlink_info_v4")
    fm = {}
    for md5, fname, fsize, d1, d2 in cur.fetchall():
        fm[md5] = {
            'name': fname,
            'size': fsize,
            'dir1': d2id.get(d1),
            'dir2': d2id.get(d2),
        }
    return fm


def unzstd(data):
    if isinstance(data, bytes) and data[:4] == b'\x28\xb5\x2f\xfd':
        try:
            return zstd.ZstdDecompressor().decompress(data).decode('utf-8', errors='ignore')
        except Exception:
            return data.decode('utf-8', errors='ignore')
    if isinstance(data, bytes):
        return data.decode('utf-8', errors='ignore')
    return str(data or '')


def scan_message_db(conn, n2id, file_map, h2name, contact, out, seen_md5):
    """扫描一个消息库的所有 Msg_* 表，提取文件消息"""
    cur = conn.cursor()
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'Msg_%'")
    tables = [r[0] for r in cur.fetchall()]
    n_files = 0
    for t in tables:
        conv_hash = t[4:]  # Msg_ 后是会话hash
        uname = h2name.get(conv_hash, '')
        cur.execute(f"SELECT local_id, create_time, real_sender_id, message_content, compress_content FROM {t}")
        for local_id, ct, sender_id, mc, cc in cur.fetchall():
            data = cc if (isinstance(cc, bytes) and len(cc) > 0) else mc
            text = unzstd(data)
            if 'type="6"' not in text and '<type>6</type>' not in text:
                continue
            title_m = re.search(r'<title>([^<]*)</title>', text)
            md5_m = re.search(r'<md5>([0-9a-f]{32})</md5>', text)
            if not md5_m:
                continue
            md5 = md5_m.group(1)
            title = html.unescape(title_m.group(1)) if title_m else ''
            if md5 in seen_md5:
                continue
            seen_md5.add(md5)
            fm = file_map.get(md5)
            if not fm:
                continue
            # 发送者名称
            if sender_id is not None:
                sender_uname = n2id.get(str(sender_id), '')
                sender_name = contact.get(sender_uname, sender_uname or '未知')
            else:
                sender_name = ''
            # 会话显示名
            conv_name = contact.get(uname, uname) if uname else '(未记录)'
            # 时间
            tstr = ''
            if ct:
                try:
                    tstr = datetime.datetime.fromtimestamp(ct).strftime('%Y-%m-%d %H:%M:%S')
                except Exception:
                    tstr = str(ct)
            # 磁盘路径：msg/file/<月份>/<磁盘文件名>（dir2 或从会话 dir1 推断）
            month = fm.get('dir2') or ''
            if isinstance(month, str) and re.match(r'^\d{4}-\d{2}$', month):
                disk_path = os.path.join(FILE_ROOT, month, fm['name'])
            else:
                disk_path = os.path.join(FILE_ROOT, fm.get('dir1') or '', fm['name'])
            exists = os.path.exists(disk_path)
            out.append({
                'time': tstr,
                'sender': sender_name,
                'conversation': conv_name,
                'conv_wxid': uname,
                'title': title,
                'disk_name': fm['name'],
                'size': fm['size'],
                'md5': md5,
                'disk_path': disk_path,
                'exists': exists,
            })
            n_files += 1
    return n_files


def main():
    ap = argparse.ArgumentParser(description='微信文件消息导出')
    ap.add_argument('--out', default='./file_messages.csv', help='输出 CSV')
    ap.add_argument('--conv', help='只导出某会话（昵称子串）')
    args = ap.parse_args()

    logger.info("加载 hardlink 文件表...")
    try:
        hl = open_db(DB_HARDLINK)
        file_map = load_file_map(hl)
        hl.close()
    except Exception as e:
        logger.warning("hardlink.db 打开/解密失败，跳过文件磁盘映射: %s", e)
        file_map = {}
    logger.info("hardlink 文件 %d 条", len(file_map))

    logger.info("加载通讯录...")
    cc = open_db(DB_CONTACT)
    contact = load_contact(cc)
    cc.close()
    logger.info("通讯录 %d 人", len(contact))

    out = []
    seen = set()
    for dbp, label in ((DB_MESSAGE_0, 'message_0'), (DB_MESSAGE_1, 'message_1')):
        conn = open_db(dbp)
        n2id, h2name = load_name2id(conn)
        n = scan_message_db(conn, n2id, file_map, h2name, contact, out, seen)
        logger.info("%s 扫描到 %d 条文件消息（新增 %d）", label, len(seen), n)
        conn.close()

    if args.conv:
        kw = args.conv.lower()
        out = [r for r in out if kw in r['conversation'].lower() or kw in r['conv_wxid'].lower()]

    with open(args.out, 'w', encoding='utf-8-sig') as f:
        f.write('时间,发送者,会话,原始文件名,磁盘文件名,大小(B),md5,磁盘路径,文件存在\n')
        for r in out:
            f.write(','.join(str(r[k]).replace(',', '，').replace('\n', ' ') for k in
                             ['time', 'sender', 'conversation', 'title', 'disk_name',
                              'size', 'md5', 'disk_path', 'exists']) + '\n')
    logger.info("导出 %d 条文件消息 -> %s", len(out), args.out)


if __name__ == '__main__':
    main()
