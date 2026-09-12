#!/usr/bin/env python3
"""微信 4.0 朋友圈(sns.db)导出：动态 + 点赞/评论 转可读文本"""
import os
import sys
import re
import sqlite3
import datetime
import argparse

try:
    import sqlcipher3
except ImportError:
    sqlcipher3 = None

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ROOT)
sys.path.insert(0, os.path.join(_ROOT, 'wxlib'))
from wx_secrets import SNS_DB, SNS_KEY, SELF_WXID, SELF_NAME, CONTACT_KEY, CONTACT_REAL


def _snap(path):
    """把微信真实目录下的库复制到本地后返回本地路径。"""
    from local_db import local_copy
    return local_copy(path)


def connect():
    if sqlcipher3 is None:
        raise RuntimeError('缺少 sqlcipher3，无法解密 sns.db')
    conn = sqlcipher3.connect(_snap(SNS_DB))
    conn.execute(f"PRAGMA key = \"x'{SNS_KEY}'\";")
    return conn


def _build_nickname_resolver():
    """wxid -> 显示名 解释器：优先 remark，其次 nick_name，最后 wxid 本身。
    来源：真实 contact.db（本地快照 + SQLCipher 解密）。"""
    resolver = {}
    try:
        conn = sqlcipher3.connect(_snap(CONTACT_REAL))
        conn.execute(f"PRAGMA key = \"x'{CONTACT_KEY}'\";")
        cur = conn.cursor()
        cur.execute('SELECT username, remark, nick_name FROM Contact')
        for username, remark, nickname in cur.fetchall():
            if not username:
                continue
            display = (remark or '').strip() or (nickname or '').strip() or username
            resolver[username] = display
        conn.close()
    except Exception as e:
        print(f"[警告] 昵称解释器加载失败: {e}")
    return resolver


def resolve_nick(resolver, username, embedded=''):
    """用解释器把 wxid 解析为显示名；取不到时回退到动态里内嵌的昵称。"""
    if username and username in resolver:
        return resolver[username]
    return (embedded or '').strip() or username or '未知用户'


def fmt_time(ts):
    if not ts:
        return ''
    try:
        return datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
    except Exception:
        return str(ts)


def clean_text(s):
    """去除零宽空格/软连字符等不可见字符后 strip（保留普通空格）。"""
    if not s:
        return ''
    return re.sub(r'[\u200b\u200c\u200d\ufeff]', '', s).strip()


def parse_media(xml):
    """从 TimelineObject.ContentObject.mediaList 提取图片/视频信息"""
    items = []
    for m in re.finditer(r'<media>(.*?)</media>', xml, re.S):
        block = m.group(1)
        mtype = re.search(r'<type>(\d+)</type>', block)
        mtype = mtype.group(1) if mtype else '0'
        size = re.search(r'<size[^>]*?width="(\d+)"[^>]*?height="(\d+)"', block)
        thumb = re.search(r'<thumb[^>]*>(http[^<]+)</thumb>', block)
        url = re.search(r'<url[^>]*>(http[^<]+)</url>', block)
        vid = re.search(r'<videoDuration>(\d+)</videoDuration>', block)
        item = {
            'type': mtype,
            'thumb': thumb.group(1) if thumb else '',
            'url': url.group(1) if url else '',
            'w': size.group(1) if size else '',
            'h': size.group(2) if size else '',
            'dur': vid.group(1) if vid and vid.group(1) != '0' else '',
        }
        items.append(item)
    return items


def parse_likes(xml):
    """从 LocalExtraInfo.like_user_list 提取点赞列表（含用户名与具体时间）"""
    likes = []
    for m in re.finditer(r'<user_comment>(.*?)</user_comment>', xml, re.S):
        block = m.group(1)
        if re.search(r'<type>1</type>', block):
            nick = re.search(r'<nickname>(.*?)</nickname>', block)
            uname = re.search(r'<username>(.*?)</username>', block)
            ct = re.search(r'<create_time>(\d+)</create_time>', block)
            likes.append({
                'nick': nick.group(1) if nick else '',
                'username': uname.group(1) if uname else '',
                'time': fmt_time(int(ct.group(1))) if ct else '',
            })
    return likes


def parse_comments(xml):
    """从 LocalExtraInfo.like_user_list 提取评论列表 (type != 1)，含用户名、时间、引用与 comment_id"""
    comments = []
    for m in re.finditer(r'<user_comment>(.*?)</user_comment>', xml, re.S):
        block = m.group(1)
        if re.search(r'<type>2</type>', block):
            nick = re.search(r'<nickname>(.*?)</nickname>', block)
            uname = re.search(r'<username>(.*?)</username>', block)
            ct = re.search(r'<create_time>(\d+)</create_time>', block)
            content = re.search(r'<content>(.*?)</content>', block, re.S)
            cid = re.search(r'<comment_id>(\d+)</comment_id>', block)
            ref_cid = re.search(r'<ref_comment_id>(\d+)</ref_comment_id>', block)
            ref_user = re.search(r'<ref_username>(.*?)</ref_username>', block)
            comments.append({
                'nick': nick.group(1) if nick else '',
                'username': uname.group(1) if uname else '',
                'time': fmt_time(int(ct.group(1))) if ct else '',
                'text': content.group(1) if content else '',
                'comment_id': cid.group(1) if cid else '',
                'ref_comment_id': ref_cid.group(1) if ref_cid else '',
                'ref_username': ref_user.group(1) if ref_user else '',
            })
    return comments


def parse_ref_buf(data):
    """解析 SnsMessage_tmp3.serialized_ref_buf（protobuf）。
    引用评论时含：f1=被引用者wxid, f3=被引用者昵称, f4=评论者昵称, f8=被引用内容。
    返回 dict 或 None。"""
    if not data or len(data) < 3:
        return None
    try:
        b = bytes(data)
    except Exception:
        return None
    i = 0
    ref = {}
    def read_varint(b, i):
        r = 0
        s = 0
        while True:
            if i >= len(b):
                raise ValueError('eof')
            v = b[i]
            i += 1
            r |= (v & 0x7f) << s
            if not v & 0x80:
                break
            s += 7
        return r, i
    while i < len(b):
        try:
            tag, i = read_varint(b, i)
        except Exception:
            break
        field = tag >> 3
        wire = tag & 7
        if wire == 0:
            _, i = read_varint(b, i)
        elif wire == 2:
            ln, i = read_varint(b, i)
            if i + ln > len(b):
                break
            sub = b[i:i + ln]
            i += ln
            if field in (1, 3, 4, 8):
                try:
                    ref[field] = sub.decode('utf-8')
                except Exception:
                    ref[field] = None
        else:
            break
    if not ref:
        return None
    return {
        'ref_username': ref.get(1),
        'ref_nickname': ref.get(3),
        'commenter_nickname': ref.get(4),
        'ref_text': ref.get(8),
    }


def parse_post(content):
    """解析 SnsTimeLine.content XML，返回结构化动态"""
    if not content:
        return None
    post = {}
    m = re.search(r'<createTime>(\d+)</createTime>', content)
    post['time'] = fmt_time(int(m.group(1))) if m else ''
    m = re.search(r'<contentDesc>(.*?)</contentDesc>', content, re.S)
    post['desc'] = m.group(1) if m else ''
    m = re.search(r'<username>(.*?)</username>', content)
    post['username'] = m.group(1) if m else ''
    post['nickname'] = ''
    m = re.search(r'<nickname>(.*?)</nickname>', content)
    if m:
        post['nickname'] = m.group(1)
    loc = re.search(r'<location[^>]*label="([^"]*)"', content)
    post['location'] = loc.group(1) if loc else ''
    post['media'] = parse_media(content)
    post['likes'] = parse_likes(content)
    post['comments'] = parse_comments(content)
    # 仅文本动态
    if not post['media'] and not post['desc']:
        return None
    return post


def build_nickname_map(conn):
    """SnsMessage_tmp3 中有 from_nickname/to_nickname，用于补齐发帖人昵称"""
    nick = {}
    cur = conn.cursor()
    try:
        cur.execute("SELECT DISTINCT from_username, from_nickname FROM SnsMessage_tmp3 WHERE from_nickname IS NOT NULL AND from_nickname != ''")
        for u, n in cur.fetchall():
            if u and n:
                nick.setdefault(u, n)
    except Exception:
        pass
    return nick


def build_display_index(resolver, nick_map):
    """构建 显示名(小写) -> {wxid,...} 反向索引，供昵称模糊匹配。"""
    index = {}
    for uname, display in resolver.items():
        key = (display or '').strip().lower()
        if key:
            index.setdefault(key, set()).add(uname)
    for uname, display in nick_map.items():
        key = (display or '').strip().lower()
        if key:
            index.setdefault(key, set()).add(uname)
    return index


def match_target(target, resolver, nick_map):
    """鲁棒性匹配输入（参考 main.py locate_conversation）：
    - 精确 wxid
    - 精确显示名（备注/昵称，不区分大小写）
    - wxid 前缀（部分 wxid）
    - 显示名模糊子串：优先真实 wxid 联系人，排除群聊/服务号/陌生人，取最短命中
    返回匹配到的 username 集合；target 为空返回 None（表示不过滤）。"""
    if not target:
        return None
    t = target.strip()
    tl = t.lower()
    if t in resolver:
        return {t}
    index = build_display_index(resolver, nick_map)
    if tl in index:
        return set(index[tl])
    if t.startswith('wxid_'):
        matched = {u for u in resolver if u.startswith(t)}
        if matched:
            return matched
    candidates = []
    for dl, us in index.items():
        if tl in dl:
            for u in us:
                if '@chatroom' in u or '@openim' in u or '@stranger' in u or u.startswith('v3_'):
                    continue
                if u.startswith('wxid_'):
                    candidates.append((len(dl), dl, u))
    if candidates:
        candidates.sort(key=lambda x: x[0])
        best_len = candidates[0][0]
        return {u for n, dl, u in candidates if n == best_len}
    return set()


def build_comment_map(conn):
    """SnsMessage_tmp3 中 type=2 的评论，按 feed_id 聚合（含历史/已删评论与引用）"""
    cmap = {}
    cur = conn.cursor()
    cur.execute("SELECT feed_id, create_time, from_username, from_nickname, to_nickname, content, serialized_ref_buf FROM SnsMessage_tmp3 WHERE type=2 AND content IS NOT NULL")
    for feed_id, ct, funame, fnick, tnick, ctext, refbuf in cur.fetchall():
        cmap.setdefault(feed_id, []).append({
            'time': fmt_time(ct),
            'username': funame or '',
            'nick': fnick or '',
            'to': tnick or '',
            'text': ctext or '',
            'ref': parse_ref_buf(refbuf),
        })
    for k in cmap:
        cmap[k].sort(key=lambda x: x['time'])
    return cmap


def build_like_map(conn):
    """SnsMessage_tmp3 中 type=1 的点赞，按 feed_id 聚合（含用户名与具体时间）"""
    lmap = {}
    cur = conn.cursor()
    cur.execute("SELECT feed_id, create_time, from_username, from_nickname FROM SnsMessage_tmp3 WHERE type=1")
    for feed_id, ct, funame, fnick in cur.fetchall():
        lmap.setdefault(feed_id, []).append({
            'time': fmt_time(ct),
            'username': funame or '',
            'nick': fnick or '',
        })
    return lmap


def build_deleted_map(comment_map, like_map, timeline_rows):
    """构建 已删除评论/点赞 集合：SnsMessage_tmp3 中有记录但当前动态 XML 中已不存在。
    返回 {feed_key: {'comments': {(username,text)}, 'likes': {username}}}"""
    xml_comments = {}
    xml_likes = {}
    for _tid, _uname, content, _pack in timeline_rows:
        m = re.search(r'<id>(\d+)</id>', content or '')
        if not m:
            continue
        feed = int(m.group(1))
        if feed >= 2 ** 63:
            feed -= 2 ** 64
        xml_comments.setdefault(feed, set())
        xml_likes.setdefault(feed, set())
        for c in parse_comments(content):
            if c['text'] and clean_text(c['text']):
                xml_comments[feed].add((c['username'], clean_text(c['text'])))
        for l in parse_likes(content):
            if l['username']:
                xml_likes[feed].add(l['username'])
    deleted = {}
    for feed, comments in comment_map.items():
        for c in comments:
            if c['text'] and clean_text(c['text']) and (c['username'], clean_text(c['text'])) not in xml_comments.get(feed, set()):
                deleted.setdefault(feed, {'comments': set(), 'likes': set()})
                deleted[feed]['comments'].add((c['username'], clean_text(c['text'])))
    for feed, likes in like_map.items():
        for l in likes:
            if l['username'] and l['username'] not in xml_likes.get(feed, set()):
                deleted.setdefault(feed, {'comments': set(), 'likes': set()})
                deleted[feed]['likes'].add(l['username'])
    return deleted


def format_ref(c, resolver, ref_lookup=None):
    """生成评论的引用标注。
    优先级：protobuf 的被引用内容 > 同动态评论链（ref_comment_id 关联）> 仅回复对象昵称。"""
    ref = c.get('ref') or {}
    ref_text = ref.get('ref_text') or ''
    ref_username = ref.get('ref_username') or c.get('ref_username') or ''
    ref_nickname = ref.get('ref_nickname') or ''
    if not ref_text and ref_lookup:
        ref_text = ref_lookup.get(c.get('ref_comment_id') or '', '')
        if not ref_text:
            ref_text = ref_lookup.get('cid_' + (c.get('comment_id') or ''), '')
    if not ref_text and not ref_username:
        return ''
    target = resolve_nick(resolver, ref_username, ref_nickname)
    if ref_text:
        return f" [引用 @{target}: {clean_text(ref_text)}]"
    return f" [引用 @{target}]"


def render(post, like_map, comment_map, resolver, deleted_map=None):
    """渲染单条动态为文本"""
    lines = []
    header = []
    if post['nickname']:
        header.append(post['nickname'])
    if post['time']:
        header.append(post['time'])
    if post['location']:
        header.append(f"📍{post['location']}")
    lines.append('【' + ' | '.join(header) + '】')
    if post['desc']:
        lines.append(post['desc'])
    for md in post['media']:
        tag = '视频' if md['type'] == '4' else ('图' if md['type'] in ('1', '2') else f"媒体{md['type']}")
        info = f"[{tag}]"
        if md['w'] and md['h']:
            info += f" {md['w']}x{md['h']}"
        if md['dur']:
            info += f" {int(md['dur'])//60}:{int(md['dur'])%60:02d}"
        lines.append('  ' + info)
    # 点赞（合并来自 XML LocalExtraInfo + SnsMessage_tmp3），昵称经解释器解析 + 具体时间
    likes = list(post['likes'])
    feed_key = None
    m = re.search(r'<id>(\d+)</id>', post['_raw'] or '')
    if m:
        feed_id = int(m.group(1))
        if feed_id >= 2 ** 63:
            feed_id -= 2 ** 64
        feed_key = feed_id
    else:
        feed_key = None
    del_comments = set()
    del_likes = set()
    if deleted_map and feed_key in deleted_map:
        del_comments = deleted_map[feed_key]['comments']
        del_likes = deleted_map[feed_key]['likes']
    if feed_key and feed_key in like_map:
        for l in like_map[feed_key]:
            name = resolve_nick(resolver, l['username'], l['nick'])
            if l['username'] and l['username'] not in [x['username'] for x in likes]:
                likes.append({'nick': name, 'username': l['username'], 'time': l['time']})
    if likes:
        like_strs = []
        seen = set()
        for l in likes:
            name = resolve_nick(resolver, l.get('username', ''), l.get('nick', ''))
            t = l.get('time', '')
            key = l.get('username') or name
            if key in seen:
                continue
            seen.add(key)
            deleted = ' (已删除)' if l.get('username') in del_likes else ''
            like_strs.append(f"{name} {t}".strip() + deleted if t else name + deleted)
        lines.append('  👍 ' + ', '.join(like_strs))
    # 评论（以 SnsMessage_tmp3 为主，XML 为辅，合并 + 引用标注）
    comments = []
    if feed_key and feed_key in comment_map:
        comments = [dict(c) for c in comment_map[feed_key] if clean_text(c['text'])]
    # XML 评论补充 map 中没有的（按 username+时间+文本去重）
    for c in post['comments']:
        if not clean_text(c['text']):
            continue
        dup = any(
            x['username'] == c['username'] and x['time'] == c['time'] and clean_text(x['text']) == clean_text(c['text'])
            for x in comments)
        if not dup:
            comments.append(c)
    comments.sort(key=lambda x: x['time'])
    # 引用内容关联表：comment_id -> 评论内容（含 XML 与 map 中的评论）
    ref_lookup = {}
    for c in comments:
        cid = str(c.get('comment_id', '') or '')
        if cid:
            ref_lookup[cid] = c['text']
    for c in post['comments']:
        cid = str(c.get('comment_id', '') or '')
        if cid and cid not in ref_lookup and c['text']:
            ref_lookup[cid] = c['text']
    for c in comments:
        name = resolve_nick(resolver, c.get('username', ''), c.get('nick', ''))
        t = c.get('time', '')
        ts = f"({t}) " if t else ""
        ref_info = format_ref(c, resolver, ref_lookup)
        deleted = ' (已删除)' if (c.get('username'), clean_text(c.get('text', ''))) in del_comments else ''
        text = clean_text(c['text']).replace('[图片]', '[图片评论]')
        lines.append(f"  💬 {name} {ts}: {text}{ref_info}{deleted}")
    lines.append('-' * 50)
    return '\n'.join(lines)


def main():
    ap = argparse.ArgumentParser(description='微信朋友圈导出')
    ap.add_argument('target', nargs='?', help='昵称/备注/wxid（精确或部分匹配，支持子串）')
    ap.add_argument('-n', '--nickname', dest='nickname', help='同位置参数：昵称/备注/wxid')
    ap.add_argument('-w', '--wxid', help='指定 wxid（精确或前缀）')
    ap.add_argument('--out', default='./moments_export.txt', help='输出文件')
    ap.add_argument('--limit', type=int, default=0, help='限制动态条数(0=全部)')
    args = ap.parse_args()

    target = args.nickname or args.target or args.wxid

    conn = connect()
    resolver = _build_nickname_resolver()
    nick_map = build_nickname_map(conn)
    like_map = build_like_map(conn)
    comment_map = build_comment_map(conn)

    matched = match_target(target, resolver, nick_map)
    if target and matched is not None and matched:
        print(f"目标匹配 {len(matched)} 个用户: {', '.join(sorted(matched))}")
    elif target:
        print(f"[警告] 未匹配到用户: {target}（导出全部）")

    cur = conn.cursor()
    cur.execute("SELECT tid, user_name, content, CAST(pack_info_buf AS BLOB) FROM SnsTimeLine ORDER BY tid DESC")
    rows = cur.fetchall()

    deleted_map = build_deleted_map(comment_map, like_map, rows)
    del_cnt = sum(len(v['comments']) + len(v['likes']) for v in deleted_map.values())
    print(f"已删除评论/点赞标记: {del_cnt} 条")

    out = []
    count = 0
    for tid, uname, content, _pack in rows:
        post = parse_post(content)
        if not post:
            continue
        post['_raw'] = content
        post['nickname'] = resolve_nick(resolver, uname, post['nickname'])
        if matched is not None and uname not in matched:
            continue
        out.append(render(post, like_map, comment_map, resolver, deleted_map))
        count += 1
        if args.limit and count >= args.limit:
            break

    conn.close()
    with open(args.out, 'w', encoding='utf-8') as f:
        f.write('\n'.join(out))
    print(f"导出 {count} 条朋友圈 -> {args.out}")

    self_cnt = sum(1 for _tid, u, _c, _p in rows if u == SELF_WXID)
    print(f"总动态 {len(rows)} 条，自己发布 {self_cnt} 条")


if __name__ == '__main__':
    main()
