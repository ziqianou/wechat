import sqlite3
import zstandard as zstd
import re
import html
import datetime
import os
import sys
import hashlib
import argparse
from bs4 import BeautifulSoup
from time_range import parse_time_range, describe as describe_range

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ROOT)
sys.path.insert(0, os.path.join(_ROOT, 'wxlib'))
import logging_config as lc
from wx_secrets import WX_BASE
logger = lc.get_logger('export_all')

# 1. 配置参数（一律从真实微信目录本地快照 + SQLCipher 解密）
DB_PATH = os.path.join(WX_BASE, 'db_storage/message/message_0.db')
CONTACT_DB_PATH = os.path.join(WX_BASE, 'db_storage/contact/contact.db')
OUTPUT_DIR = './all_chats'

from local_db import local_copy, key_for
import sqlcipher3


def _open(path):
    """本地快照 + 按密钥解密打开。"""
    local = local_copy(path)
    key = key_for(local)
    if key:
        conn = sqlcipher3.connect(local)
        conn.execute(f"PRAGMA key = \"x'{key}'\";")
        return conn
    return sqlite3.connect(local)

# 2. 清洗逻辑函数与 XML 转文字处理
def clean_text_noise(text):
    """移除常见的元数据噪声，如用户ID等，安全保留聊天中的正常数字"""
    if not text:
        return ""
    # 移除 wxid_...
    text = re.sub(r'wxid_\w+', '', text)
    # 只移除10位及以上的超长独立数字（通常是时间戳、消息ID等残留），保留日常聊天数字
    text = re.sub(r'\b\d{10,}\b', '', text)
    # 移除单独的 "view"
    text = re.sub(r'\bview\b', '', text, flags=re.IGNORECASE)
    # 移除 extra whitespace
    return re.sub(r'\s+', ' ', text).strip()

def transform_xml_to_text(xml_str):
    if not xml_str or not isinstance(xml_str, str):
        return xml_str
        
    # 万能剥离：在 XML 转换入口处，自动匹配并剔除可能随附在底层的发送者前缀 (如 "wxid_xxxx:\n")
    # 这样能让递归解析（例如被引用的名片、K歌卡片、图片等）完美触发 XML 转换引擎
    xml_clean = xml_str.strip()
    prefix_match = re.match(r'^([a-zA-Z0-9_\-\@\.]+):\s*\n', xml_clean)
    if prefix_match:
        xml_clean = xml_clean[prefix_match.end():].strip()
    else:
        prefix_xml_match = re.match(r'^([a-zA-Z0-9_\-\@\.]+):\s*(?=<)', xml_clean)
        if prefix_xml_match:
            xml_clean = xml_clean[prefix_xml_match.end():].strip()
            
    if not xml_clean.startswith('<'):
        return xml_str
        
    try:
        # 1. 尝试修复可能损坏的 XML 根结构
        if xml_clean.count('<msg') > 1 and xml_clean.count('</msg') == 0:
            xml_clean = xml_clean.replace('<msg', '<root><msg', 1) + '</root>'
        
        soup = BeautifulSoup(xml_clean, 'xml')
        
        # 1.1 名片消息 (个人名片 / 公众号名片)
        msg_node = soup.find('msg')
        if msg_node and msg_node.get('nickname') and msg_node.get('username'):
            nickname = msg_node.get('nickname')
            username = msg_node.get('username')
            is_brand = username.startswith("gh_")
            card_type = "公众号名片" if is_brand else "个人名片"
            
            prov = msg_node.get('province') or ""
            city = msg_node.get('city') or ""
            loc_str = f"地区: {prov} {city}".strip()
            loc_str = f", {loc_str}" if loc_str else ""
            
            sign = msg_node.get('sign') or msg_node.get('certinfo')
            sign_str = f", 签名: {sign}" if sign and sign.strip() else ""
            
            return f"[{card_type}]({nickname}, 微信号: {username}{loc_str}{sign_str})"
        
        # 1.2 系统提示与模板消息 (sysmsg / sysmsgtemplate)
        if soup.find('sysmsg'):
            sysmsg_node = soup.find('sysmsg')
            sysmsg_type = sysmsg_node.get('type')
            if sysmsg_type == 'sysmsgtemplate':
                tmpl_node = soup.find('template')
                if tmpl_node:
                    template_text = tmpl_node.get_text().strip()
                    link_map = {}
                    for link in soup.find_all('link'):
                        link_name = link.get('name')
                        if not link_name:
                            continue
                        members = []
                        for m in link.find_all('member'):
                            nick = m.find('nickname')
                            title_tag = m.find('title')
                            usr = m.find('username')
                            m_text = nick.get_text() if nick else (title_tag.get_text() if title_tag else (usr.get_text() if usr else ""))
                            if m_text:
                                members.append(m_text.strip())
                        sep_node = link.find('separator')
                        sep = sep_node.get_text() if sep_node else "、"
                        link_map[link_name] = sep.join(members)
                    
                    for k, v in link_map.items():
                        template_text = template_text.replace(f"${k}$", v)
                    template_text = re.sub(r'\$\w+\$', '', template_text)
                    return f"[系统消息] {template_text}"
            elif sysmsg_type == 'revokemsg':
                content_node = soup.find('content')
                if content_node:
                    return f"[系统消息] {content_node.get_text().strip()}"
            elif '红包' in xml_clean:
                return '[红包消息]'
        
        # 1.3 VoIP 通话消息 (voipmsg)
        if soup.find('voipmsg'):
            voip_node = soup.find('VoIPBubbleMsg')
            if voip_node:
                msg_text = voip_node.find('msg').get_text().strip() if voip_node.find('msg') else "通话"
                r_type = voip_node.find('room_type')
                room_type = r_type.get_text().strip() if r_type else "1"
                
                # room_type = 1 为语音通话，2 为视频通话
                call_type = "视频通话" if room_type == "2" else "语音通话"
                
                # 获取通话时长 (秒)
                dur_node = voip_node.find('duration')
                duration = int(dur_node.get_text().strip()) if dur_node and dur_node.get_text().strip().isdigit() else 0
                
                if duration > 0:
                    minutes = duration // 60
                    seconds = duration % 60
                    dur_str = f"通话时长: {minutes:02d}:{seconds:02d}" if minutes > 0 else f"通话时长: {seconds}秒"
                    return f"[{call_type}]({msg_text}, {dur_str})"
                else:
                    return f"[{call_type}]({msg_text})"
        
        # 2. 合并转发/聊天记录 (深度解析)
        # 限制：仅当 recorditem 不是 nested inside refermsg 时才作为 top-level 的合并消息处理
        recorditem = soup.find('recorditem')
        if recorditem and not recorditem.find_parent('refermsg'):
            record_xml = recorditem.get_text()
            messages = []
            if record_xml:
                record_soup = BeautifulSoup(record_xml, 'xml')
                for item in record_soup.find_all('dataitem'):
                    sender = item.find('sourcename').text if item.find('sourcename') else "未知"
                    content_tag = item.find('datadesc')
                    content = content_tag.text if content_tag else ""
                    
                    # 如果转发项里有嵌套的 XML，也可以尝试剥离前缀解析，否则用 text
                    if content.strip().startswith('<') or '<msg' in content:
                        content = transform_xml_to_text(content)
                    else:
                        content = clean_text_noise(content)
                        
                    messages.append(f"{sender}: {content}")
            
            if messages:
                return "[合并消息]{\n  " + "\n  ".join(messages) + "\n}"
            else:
                # 如果 recorditem 为空，说明它可能是被折叠或空的聊天记录，退化为显示聊天记录标题
                appmsg_node = soup.find('appmsg')
                title = "聊天记录"
                if appmsg_node and appmsg_node.find('title'):
                    title = appmsg_node.find('title').get_text(strip=True)
                return f"[聊天记录]({title})"

        # 3. 其它消息类型
        if soup.find('img'): return '[图片]'
        if soup.find('emoji'): return '[动画表情]'
        if soup.find('videomsg'): return '[视频消息]'
        if soup.find('voicemsg'):
            voice_node = soup.find('voicemsg')
            length_ms = voice_node.get('voicelength')
            if length_ms and length_ms.isdigit():
                seconds = round(int(length_ms) / 1000)
                if seconds == 0 and int(length_ms) > 0:
                    seconds = 1
                return f"[语音消息]({seconds}秒)"
            return "[语音消息]"
        if soup.find('location'):
            label = soup.find('location').get('label', '位置')
            return f"[位置]({label})"
        if soup.find('patinfo'):
            title = soup.find('title').text if soup.find('title') else "拍一拍"
            return f"[拍一拍]({title})"

        # 4. 引用 (refermsg)
        # 限制：仅当 refermsg 不是 nested inside recorditem 时才作为 top-level 的引用消息处理
        refermsg = soup.find('refermsg')
        if refermsg and not refermsg.find_parent('recorditem'):
            ref_sender = refermsg.find('displayname').text if refermsg.find('displayname') else "未知"
            ref_content_tag = refermsg.find('content')
            
            ref_content = ""
            if ref_content_tag:
                # 获取引用文本的内层 XML 表示
                inner_xml = html.unescape(ref_content_tag.decode_contents()).strip()
                if inner_xml.startswith('<') or '<msg' in inner_xml:
                    # 递归解析嵌套的被引用消息（如引用了图片、名片、位置、文件等）
                    ref_content = transform_xml_to_text(inner_xml)
                else:
                    # 如果只是普通纯文本，进行正常文本清洗
                    ref_content = clean_text_noise(ref_content_tag.get_text(separator=' ', strip=True))
            
            main_content = ""
            appmsg = soup.find('appmsg')
            if appmsg and appmsg.find('title'):
                main_content = appmsg.find('title').get_text(strip=True)
                
            return f"{main_content}[引用]({ref_sender}: {ref_content})"

        # 5. Appmsg (文件、卡片等)
        appmsg = soup.find('appmsg')
        if appmsg:
            msg_type = appmsg.find('type')
            msg_type_str = msg_type.text if msg_type else ""
            title = appmsg.find('title').text if appmsg.find('title') else "卡片消息"
            if msg_type_str == '6': 
                return f"[文件]({title})"
            elif msg_type_str == '19':
                return f"[聊天记录]({title})"
            elif msg_type_str == '57':
                # 如果是引用消息，但没有 refermsg 标签或者 refermsg 为空，
                # 我们直接返回它的 title (原消息文本)
                return title
            else: 
                return f"[卡片]({title})"

        # 6. 普通文本 fallback
        if soup.find('title'): return soup.find('title').text
        if soup.find('content') and soup.find('content').text: return soup.find('content').text
        
    except Exception as e:
        return f"[解析失败] {xml_str[:50]}..."
        
    return xml_str

def process_message_content(data):
    """解压数据并清洗格式"""
    if not isinstance(data, bytes):
        text = str(data)
    else:
        # 解压
        if data.startswith(b'\x28\xb5\x2f\xfd'):
            try:
                dctx = zstd.ZstdDecompressor()
                text = dctx.decompress(data).decode('utf-8', errors='ignore')
            except:
                text = data.decode('utf-8', errors='ignore')
        else:
            text = data.decode('utf-8', errors='ignore')
            
    # 剥离群聊消息中自带的发送者前缀 (形如 "wxid_xxxx:\n" 或 "xxxx:\n")
    # 这样能让 transform_xml_to_text 正确识别以 '<' 开头的 XML 消息
    text_clean = text
    prefix_match = re.match(r'^([a-zA-Z0-9_\-\@\.]+):\s*\n', text)
    if prefix_match:
        text_clean = text[prefix_match.end():]
    else:
        # 兼容无换行直接接 XML 的情况 (形如 "wxid_xxxx:<msg>")
        prefix_xml_match = re.match(r'^([a-zA-Z0-9_\-\@\.]+):\s*(?=<)', text)
        if prefix_xml_match:
            text_clean = text[prefix_xml_match.end():]
    
    # HTML 反转义，保证 BeautifulSoup 解析时嵌套的 XML 标记可以被识别为标签
    unescaped = html.unescape(text_clean)
    
    # 解析并简化 XML 内容
    return transform_xml_to_text(unescaped)

def clean_filename(filename):
    """移除 Windows/Linux 文件名非法字符"""
    return re.sub(r'[\/*?:"<>|]', '_', filename)

# 3. 动态加载映射信息
def load_sender_and_session_map(db_path, contact_db_path):
    """
    加载实发者映射与会话信息
    """
    sender_map = {}
    contact_map = {} # user_name -> Display Name (Remark or NickName)
    
    # 1. 尝试从 Contact 数据库中获取所有联系人的备注或昵称
    if contact_db_path and os.path.exists(contact_db_path):
        try:
            conn_c = _open(contact_db_path)
            cursor_c = conn_c.cursor()
            
            # 自适应列名大小写及下划线
            cursor_c.execute("PRAGMA table_info(Contact)")
            cols_map = {row[1].lower(): row[1] for row in cursor_c.fetchall()}
            
            u_col = cols_map.get('username', 'username')
            r_col = cols_map.get('remark', 'remark')
            n_col = cols_map.get('nick_name', cols_map.get('nickname', 'nick_name'))
            
            cursor_c.execute(f"SELECT {u_col}, {r_col}, {n_col} FROM Contact")
            for row in cursor_c.fetchall():
                username, remark, nickname = row
                display_name = remark.strip() if remark and remark.strip() else (nickname.strip() if nickname and nickname.strip() else username)
                if display_name:
                    contact_map[username] = display_name
            conn_c.close()
            print(f"[信息] 成功从 {contact_db_path} 加载了 {len(contact_map)} 个联系人的备注/昵称映射。")
        except Exception as e:
            print(f"[警告] 读取 Contact 表失败: {e}")

    # 2. 尝试从 Message 数据库的 Name2Id 中获取所有映射
    name2id = {}
    if os.path.exists(db_path):
        try:
            conn = _open(db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT rowid, user_name FROM Name2Id")
            name2id = {str(row[0]): row[1] for row in cursor.fetchall()}
            conn.close()
            print(f"[信息] 成功从 {db_path} 加载了 {len(name2id)} 个会话标识关联。")
        except Exception as e:
            print(f"[警告] 读取 Name2Id 表失败: {e}")

    # 3. 合并为 real_sender_id 映射
    for rowid, username in name2id.items():
        display_name = contact_map.get(username)
        if display_name:
            sender_map[rowid] = display_name
        else:
            sender_map[rowid] = username

    return sender_map, contact_map, name2id

# 4. 主程序：批量导出所有聊天记录
def main():
    parser = argparse.ArgumentParser(description='批量导出所有微信聊天记录')
    parser.add_argument('--range', '-r', default=None,
                        help='时间范围，如 20260702-20260807、1d、1w、1m、1y、today、yesterday（默认全部）')
    args = parser.parse_args()

    start_ts, end_ts = parse_time_range(args.range)
    print(f"[信息] 导出范围: {describe_range(args.range, start_ts, end_ts)}")

    if not os.path.exists(DB_PATH):
        print(f"[错误] 消息数据库不存在，请确认当前目录下有 {DB_PATH} 文件。")
        return

    # 创建输出目录
    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)
        print(f"[信息] 已创建导出目录: {OUTPUT_DIR}")

    # 加载映射字典
    sender_map, contact_map, name2id = load_sender_and_session_map(DB_PATH, CONTACT_DB_PATH)

    # 获取数据库里所有已存在的消息表
    conn = _open(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'Msg_%'")
    msg_tables = {row[0] for row in cursor.fetchall()}

    print(f"[信息] 数据库中共有 {len(msg_tables)} 个消息表，正在处理中...")

    exported_count = 0
    used_filenames = set()

    for rowid_str, username in name2id.items():
        # 1. 对应消息表
        h = hashlib.md5(username.encode('utf-8')).hexdigest()
        table_name = f"Msg_{h}"
        
        if table_name not in msg_tables:
            continue # 该会话并没有实际的消息表
            
        # 2. 检查表里是否有数据（排除无聊天记录的空表）
        cursor.execute(f"SELECT COUNT(*) FROM {table_name}")
        msg_count = cursor.fetchone()[0]
        if msg_count == 0:
            continue

        # 3. 确定该会话在导出时的文件名
        # 优先使用联系人备注或昵称，其次使用微信原始ID
        session_name = contact_map.get(username, username)
        safe_session_name = clean_filename(session_name)
        
        # 解决重名冲突：如果文件名已经被占用（可能有多个相同昵称），在后面加上微信号/行号
        output_filename = f"{safe_session_name}.txt"
        if output_filename.lower() in used_filenames:
            # 采用 "昵称_微信号.txt" 来唯一区分
            output_filename = f"{safe_session_name}_{clean_filename(username)}.txt"
            # 如果还重名（极罕见），加上 rowid_str
            if output_filename.lower() in used_filenames:
                output_filename = f"{safe_session_name}_{clean_filename(username)}_{rowid_str}.txt"
                
        used_filenames.add(output_filename.lower())
        file_path = os.path.join(OUTPUT_DIR, output_filename)

        # 4. 执行本会话的所有消息读取与导出
        try:
            where = []
            params = []
            if start_ts is not None:
                where.append("create_time >= ?")
                params.append(start_ts)
            if end_ts is not None:
                where.append("create_time < ?")
                params.append(end_ts)
            where_sql = f" WHERE {' AND '.join(where)}" if where else ""
            cursor.execute(
                f"SELECT real_sender_id, message_content, create_time FROM {table_name}{where_sql} ORDER BY create_time ASC",
                params,
            )
            rows = cursor.fetchall()
            if not rows:
                continue

            with open(file_path, 'w', encoding='utf-8') as f:
                for row in rows:
                    sender_id, content, create_time = row
                    
                    # 发信人名称映射
                    sender_name = sender_map.get(str(sender_id), f"未知用户({sender_id})")
                    
                    # 格式化时间 [YYYY-MM-DD HH:MM:SS]
                    formatted_time = ""
                    if create_time:
                        try:
                            dt = datetime.datetime.fromtimestamp(create_time)
                            formatted_time = f"[{dt.strftime('%Y-%m-%d %H:%M:%S')}] "
                        except Exception:
                            pass
                            
                    # 处理消息正文
                    final_content = process_message_content(content)
                    
                    # 写入行
                    f.write(f"{formatted_time}{sender_name}: {final_content}\n")
                    
            # 将文件的修改时间（mtime）和访问时间（atime）修改为最后一条消息的时间
            if rows:
                last_create_time = rows[-1][2]
                if last_create_time:
                    try:
                        os.utime(file_path, (last_create_time, last_create_time))
                    except Exception as e:
                        print(f"[警告] 修改文件 {file_path} 时间属性失败: {e}")
                    
            exported_count += 1
            if exported_count % 10 == 0 or exported_count == len(msg_tables):
                print(f"-> 已导出 {exported_count} 个会话...")
        except Exception as e:
            print(f"[警告] 导出会话 {username} (表 {table_name}) 失败: {e}")

    conn.close()
    print("\n" + "="*50)
    print(f"🎉 恭喜！所有聊天记录导出成功！")
    print(f"📂 导出目录：{os.path.abspath(OUTPUT_DIR)}")
    print(f"📊 共成功导出：{exported_count} 个有记录的会话")
    print("="*50)

if __name__ == '__main__':
    main()
