import sys
import os
import re
import html
import sqlite3
import datetime
import argparse
import zstandard as zstd
from bs4 import BeautifulSoup
from time_range import parse_time_range, describe as describe_range

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'tempfile', 'decrypt_v4'))
from wx_secrets import WX_BASE, SELF_WXID, SELF_NAME, DB_KEYS
import media_tools as mt
import logging_config as lc

logger = lc.get_logger('main')

# 1. 配置参数（可通过 run.sh 传入昵称）
DEFAULT_CONTACT = os.environ.get('WECHAT_CONTACT', '')

# 数据库密钥（真实目录为 SQLCipher 加密，需解密）


def _decrypt_db_path(db_name):
    """返回真实目录加密库的本地快照连接参数（先复制到本地，不污染微信目录）。"""
    enc_path = os.path.join(WX_BASE, 'db_storage', db_name)
    key = DB_KEYS.get(os.path.basename(db_name))
    if key and os.path.exists(enc_path):
        return {'path': _snap(enc_path), 'key': key}
    return None


def _snap(path):
    """把微信真实目录下的库复制到本地后返回本地路径。"""
    from local_db import local_copy
    return local_copy(path)


def open_db_conn(db_name):
    """打开数据库连接（解密或明文，微信目录先复制到本地）。返回 conn 或 None"""
    info = _decrypt_db_path(db_name)
    if info:
        import sqlcipher3 as sqlite3
        conn = sqlite3.connect(info['path'])
        conn.execute(f"PRAGMA key = \"x'{info['key']}'\";")
        return conn
    return None


def _smart_connect(path):
    """智能连接：按本地快照路径推断密钥并解密（微信真实目录先复制到本地）。返回 conn 或抛异常"""
    path = _snap(path)
    key = DB_KEYS.get(os.path.basename(path)) or DB_KEYS.get(os.path.basename(path).split('_', 1)[-1])
    if key:
        import sqlcipher3 as s3
        conn = s3.connect(path)
        conn.execute(f"PRAGMA key = \"x'{key}'\";")
        return conn
    return sqlite3.connect(path)


DB_PATH = None
CONTACT_DB_PATH = None
MEDIA_DB_PATH = None
HARDLINK_DB_PATH = None
ATTACH_ROOT = os.path.join(WX_BASE, 'msg', 'attach')

# 全部数据库一律从真实目录本地快照 + SQLCipher 解密
_enc_msg = _decrypt_db_path('message/message_0.db')
if _enc_msg:
    DB_PATH = _enc_msg['path']
_enc_contact = _decrypt_db_path('contact/contact.db')
if _enc_contact:
    CONTACT_DB_PATH = _enc_contact['path']
_enc_media = _decrypt_db_path('message/media_0.db')
if _enc_media:
    MEDIA_DB_PATH = _enc_media['path']
_enc_hardlink = _decrypt_db_path('hardlink/hardlink.db')
if _enc_hardlink:
    HARDLINK_DB_PATH = _enc_hardlink['path']
logger.debug("DB_PATH=%s", DB_PATH)
logger.debug("CONTACT_DB_PATH=%s", CONTACT_DB_PATH)
logger.debug("MEDIA_DB_PATH=%s", MEDIA_DB_PATH)
logger.debug("HARDLINK_DB_PATH=%s", HARDLINK_DB_PATH)
logger.debug("ATTACH_ROOT=%s", ATTACH_ROOT)

# 控制是否启用 OCR / 视觉描述 / 语音转文字（可环境变量关闭）
# 默认: OCR 开、VLM 描述关(慢)、语音转文字开
ENABLE_OCR = os.environ.get('WECHAT_OCR', '1') == '1'
ENABLE_VLM = os.environ.get('WECHAT_VLM', '0') == '1'
ENABLE_ASR = os.environ.get('WECHAT_ASR', '1') == '1'

# 缓存目录（媒体处理结果复用，实现增量）
CACHE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'tempfile', 'decrypt_v4', 'cache')
IMG_CACHE = os.path.join(CACHE_DIR, 'images')
VOICE_CACHE = os.path.join(CACHE_DIR, 'voices')
STATE_FILE = os.path.join(CACHE_DIR, 'state.json')
os.makedirs(IMG_CACHE, exist_ok=True)
os.makedirs(VOICE_CACHE, exist_ok=True)


def load_state():
    if os.path.exists(STATE_FILE):
        try:
            import json
            with open(STATE_FILE, encoding='utf-8') as f:
                state = json.load(f)
            logger.debug("加载增量状态文件: %s (%d 个会话)", STATE_FILE, len(state.get('conversations', {})))
            return state
        except Exception as e:
            logger.warning("读取状态文件失败 %s: %s", STATE_FILE, e)
            return {}
    logger.debug("状态文件不存在，从空状态开始: %s", STATE_FILE)
    return {}


def save_state(state):
    import json
    with open(STATE_FILE, 'w', encoding='utf-8') as f:
        json.dump(state, f, ensure_ascii=False, indent=2)
    logger.debug("已保存增量状态到 %s", STATE_FILE)


def process_image_cached(md5, img_resolver, msg_time=None, missing_collector=None):
    """图片 OCR + 描述，带缓存。返回标注字符串或 None"""
    ocr_cache = os.path.join(IMG_CACHE, md5 + '.ocr')
    desc_cache = os.path.join(IMG_CACHE, md5 + '.desc')
    have_ocr = os.path.exists(ocr_cache)
    have_desc = os.path.exists(desc_cache)
    logger.debug("图片处理 md5=%s ocr缓存=%s desc缓存=%s", md5, have_ocr, have_desc)

    # 读取已有缓存（不需要解密/ffmpeg）
    parts = []
    if have_ocr:
        ocr_txt = open(ocr_cache, encoding='utf-8').read().strip()
        if ocr_txt:
            parts.append('文字: ' + ocr_txt)
    if have_desc:
        desc_txt = open(desc_cache, encoding='utf-8').read().strip()
        if desc_txt:
            parts.append('描述: ' + desc_txt)

    need_ocr = ENABLE_OCR and not have_ocr
    need_desc = ENABLE_VLM and not have_desc
    # 本地无 dat 文件：即使已有缓存也要计入缺失统计（缓存完整时照常返回标注）
    p = img_resolver.get(md5)
    if not p or not os.path.exists(p):
        logger.debug("图片 md5=%s 本地无 dat 文件，跳过 (消息时间 %s)", md5, msg_time or '未知')
        if missing_collector is not None:
            missing_collector.append({'md5': md5, 'time': msg_time})
        if not need_ocr and not need_desc:
            return '；'.join(parts) if parts else None
        return None

    # 如果该 md5 需要的结果已全部缓存，直接返回
    if not need_ocr and not need_desc:
        logger.debug("图片 md5=%s 全部命中缓存，直接返回", md5)
        return '；'.join(parts) if parts else None
    try:
        dat_bytes = open(p, 'rb').read()
        logger.debug("读取图片 dat 文件: %s (%d 字节)", p, len(dat_bytes))
        img_bytes, ext, is_wxgf, h265 = mt.convert_v4(dat_bytes)
        logger.debug("解密图片 md5=%s 格式=%s wxgf=%s", md5, ext, is_wxgf)
        if is_wxgf:
            logger.debug("wxgf 图片 md5=%s，通过 ffmpeg 转 JPEG", md5)
            img_bytes = mt.wxgf_to_jpg_bytes(h265) or img_bytes
            ext = 'jpg'
        suffix = ext if ext in ('jpg', 'png', 'gif', 'bmp', 'tiff') else 'jpg'
        if need_ocr:
            try:
                lines = mt.ocr_image(img_bytes, suffix)
                if lines:
                    ocr_txt = ' | '.join(lines)
                    with open(ocr_cache, 'w', encoding='utf-8') as f:
                        f.write(ocr_txt)
                    parts.append('文字: ' + ocr_txt)
                    logger.debug("OCR md5=%s 识别到 %d 行", md5, len(lines))
                else:
                    with open(ocr_cache, 'w', encoding='utf-8') as f:
                        f.write('')
                    logger.debug("OCR md5=%s 无文字，已写入空缓存", md5)
            except Exception as e:
                logger.warning("OCR 失败 md5=%s: %s", md5, e)
        if need_desc:
            try:
                desc = mt.describe_image(img_bytes, suffix)
                if desc:
                    desc = desc.strip()
                    with open(desc_cache, 'w', encoding='utf-8') as f:
                        f.write(desc)
                    parts.append('描述: ' + desc)
                    logger.debug("VLM md5=%s 生成描述: %s", md5, desc[:60])
            except Exception as e:
                logger.warning("VLM 描述失败 md5=%s: %s", md5, e)
        return '；'.join(parts) if parts else None
    except Exception as e:
        logger.warning("解密图片失败 md5=%s (%s): %s", md5, p, e)
        return f'解密失败: {e}'


def process_voice_cached(local_id, voice_map):
    """语音转文字，带缓存"""
    cache_f = os.path.join(VOICE_CACHE, f'{local_id}.txt')
    if os.path.exists(cache_f):
        txt = open(cache_f, encoding='utf-8').read().strip()
        logger.debug("语音 local_id=%s 命中缓存", local_id)
        return f'[语音→文字]({txt})' if txt else '[语音消息]'
    vd = voice_map.get(local_id)
    if not vd:
        logger.debug("语音 local_id=%s 无媒体数据，返回占位", local_id)
        return '[语音消息]'
    try:
        logger.info("语音转文字 local_id=%s，调用 Whisper", local_id)
        txt = voice_to_text(vd[1])
        if txt:
            with open(cache_f, 'w', encoding='utf-8') as f:
                f.write(txt)
            logger.debug("语音 local_id=%s 转写完成: %s", local_id, txt[:50])
            return f'[语音→文字]({txt})'
    except Exception as e:
        logger.warning("语音转写失败 local_id=%s: %s", local_id, e)
    return '[语音消息]'


def load_sender_map(db_path, contact_db_path, self_name=''):
    """构建 real_sender_id -> 昵称 的映射"""
    sender_map = {}
    name2id = {}
    if os.path.exists(db_path):
        try:
            conn = _smart_connect(db_path)
            cur = conn.cursor()
            cur.execute("SELECT rowid, user_name FROM Name2Id")
            name2id = {str(row[0]): row[1] for row in cur.fetchall()}
            conn.close()
            logger.debug("消息库 Name2Id 加载 %d 条映射", len(name2id))
        except Exception as e:
            logger.warning("读取 Name2Id 失败: %s", e)
    contact_map = {}
    if contact_db_path and os.path.exists(contact_db_path):
        try:
            conn_c = _smart_connect(contact_db_path)
            cur_c = conn_c.cursor()
            cur_c.execute("PRAGMA table_info(Contact)")
            cols_map = {row[1].lower(): row[1] for row in cur_c.fetchall()}
            u_col = cols_map.get('username', 'username')
            r_col = cols_map.get('remark', 'remark')
            n_col = cols_map.get('nick_name', cols_map.get('nickname', 'nick_name'))
            cur_c.execute(f"SELECT {u_col}, {r_col}, {n_col} FROM Contact")
            for row in cur_c.fetchall():
                username, remark, nickname = row
                display = remark.strip() if remark and remark.strip() else (
                    nickname.strip() if nickname and nickname.strip() else username)
                if display:
                    contact_map[username] = display
            conn_c.close()
            logger.debug("通讯录 Contact 加载 %d 个联系人", len(contact_map))
        except Exception as e:
            logger.warning("读取 Contact 表失败: %s", e)
    for rowid, username in name2id.items():
        if username == SELF_WXID:
            sender_map[rowid] = self_name
        else:
            sender_map[rowid] = contact_map.get(username, username)
    logger.debug("构建发送者映射完成，共 %d 项（self_name=%s）", len(sender_map), self_name)
    return sender_map


def clean_text_noise(text):
    if not text:
        return ""
    text = re.sub(r'wxid_\w+', '', text)
    text = re.sub(r'\b\d{10,}\b', '', text)
    text = re.sub(r'\bview\b', '', text, flags=re.IGNORECASE)
    return re.sub(r'\s+', ' ', text).strip()


def transform_xml_to_text(xml_str):
    """复用原 main.py 的 XML 解析逻辑，图片/语音消息返回结构化占位"""
    if not xml_str or not isinstance(xml_str, str):
        return xml_str
    # 快速路径：非 XML 文本直接返回
    stripped = xml_str.strip()
    if not stripped.startswith('<'):
        return stripped
    xml_clean = stripped
    prefix_match = re.match(r'^([a-zA-Z0-9_\-\@\.]+):\s*\n', xml_clean)
    if prefix_match:
        xml_clean = xml_clean[prefix_match.end():].strip()
    else:
        prefix_xml_match = re.match(r'^([a-zA-Z0-9_\-\@\.]+):\s*(?=<)', xml_clean)
        if prefix_xml_match:
            xml_clean = xml_clean[prefix_xml_match.end():].strip()
    if not xml_clean.startswith('<'):
        return clean_text_noise(xml_clean)
    try:
        if xml_clean.count('<msg') > 1 and xml_clean.count('</msg') == 0:
            xml_clean = xml_clean.replace('<msg', '<root><msg', 1) + '</root>'
        soup = BeautifulSoup(xml_clean, 'xml')

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

        if soup.find('voipmsg'):
            voip_node = soup.find('VoIPBubbleMsg')
            if voip_node:
                msg_text = voip_node.find('msg').get_text().strip() if voip_node.find('msg') else "通话"
                r_type = voip_node.find('room_type')
                room_type = r_type.get_text().strip() if r_type else "1"
                call_type = "视频通话" if room_type == "2" else "语音通话"
                dur_node = voip_node.find('duration')
                duration = int(dur_node.get_text().strip()) if dur_node and dur_node.get_text().strip().isdigit() else 0
                if duration > 0:
                    minutes = duration // 60
                    seconds = duration % 60
                    dur_str = f"通话时长: {minutes:02d}:{seconds:02d}" if minutes > 0 else f"通话时长: {seconds}秒"
                    return f"[{call_type}]({msg_text}, {dur_str})"
                else:
                    return f"[{call_type}]({msg_text})"

        recorditem = soup.find('recorditem')
        if recorditem and not recorditem.find_parent('refermsg'):
            record_xml = recorditem.get_text()
            messages = []
            if record_xml:
                record_soup = BeautifulSoup(record_xml, 'xml')
                for item in record_soup.find_all('dataitem'):
                    sender = item.find('sourcename').text if item.find('sourcename') else "未知"
                    sourcetime_tag = item.find('sourcetime')
                    sourcetime = sourcetime_tag.text.strip() if sourcetime_tag and sourcetime_tag.text else ""
                    if sourcetime:
                        sourcetime = re.sub(r'\s+', ' ', sourcetime).strip()
                    content_tag = item.find('datadesc')
                    content = content_tag.text if content_tag else ""
                    if content.strip().startswith('<') or '<msg' in content:
                        content = transform_xml_to_text(content)
                    else:
                        content = clean_text_noise(content)
                    if sourcetime:
                        messages.append(f"[{sourcetime}] {sender}: {content}")
                    else:
                        messages.append(f"{sender}: {content}")
            if messages:
                return "[合并消息]{\n  " + "\n  ".join(messages) + "\n}"
            else:
                appmsg_node = soup.find('appmsg')
                title = "聊天记录"
                if appmsg_node and appmsg_node.find('title'):
                    title = appmsg_node.find('title').get_text(strip=True)
                return f"[聊天记录]({title})"

        # 图片消息：返回标记，由外层处理 OCR/描述
        img_node = soup.find('img')
        if img_node:
            md5 = img_node.get('md5') or img_node.get('originsourcemd5') or ''
            aeskey = img_node.get('aeskey', '')
            return f'<IMG md5="{md5}" aeskey="{aeskey}" hdlength="{img_node.get("hdlength","")}" length="{img_node.get("length","")}">'

        if soup.find('emoji'):
            return '[动画表情]'
        if soup.find('videomsg'):
            return '[视频消息]'
        if soup.find('voicemsg'):
            voice_node = soup.find('voicemsg')
            length_ms = voice_node.get('voicelength')
            sec = ''
            if length_ms and length_ms.isdigit():
                seconds = round(int(length_ms) / 1000)
                if seconds == 0 and int(length_ms) > 0:
                    seconds = 1
                sec = f"{seconds}秒"
            voiceurl = voice_node.get('voiceurl', '')
            return f'<VOICE length="{length_ms}" sec="{sec}" voiceurl="{voiceurl}">'
        if soup.find('location'):
            label = soup.find('location').get('label', '位置')
            return f"[位置]({label})"
        if soup.find('patinfo'):
            title = soup.find('title').text if soup.find('title') else "拍一拍"
            return f"[拍一拍]({title})"

        refermsg = soup.find('refermsg')
        if refermsg and not refermsg.find_parent('recorditem'):
            ref_sender = refermsg.find('displayname').text if refermsg.find('displayname') else "未知"
            ref_content_tag = refermsg.find('content')
            ref_content = ""
            if ref_content_tag:
                inner_xml = html.unescape(ref_content_tag.decode_contents()).strip()
                if inner_xml.startswith('<') or '<msg' in inner_xml:
                    ref_content = transform_xml_to_text(inner_xml)
                else:
                    ref_content = clean_text_noise(ref_content_tag.get_text(separator=' ', strip=True))
            main_content = ""
            appmsg = soup.find('appmsg')
            if appmsg and appmsg.find('title'):
                main_content = appmsg.find('title').get_text(strip=True)
            return f"{main_content}[引用]({ref_sender}: {ref_content})"

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
                return title
            else:
                return f"[卡片]({title})"

        if soup.find('title'):
            return soup.find('title').text
        if soup.find('content') and soup.find('content').text:
            return soup.find('content').text
    except Exception as e:
        logger.debug("XML 解析失败: %s | %s", e, xml_str[:80])
        return f"[解析失败] {xml_str[:50]}..."
    return xml_str


def process_message_content(data):
    """解压并解析消息内容"""
    if not isinstance(data, bytes):
        text = str(data)
    else:
        if data.startswith(b'\x28\xb5\x2f\xfd'):
            try:
                dctx = zstd.ZstdDecompressor()
                text = dctx.decompress(data).decode('utf-8', errors='ignore')
            except Exception:
                text = data.decode('utf-8', errors='ignore')
        else:
            text = data.decode('utf-8', errors='ignore')
    text_clean = text
    prefix_match = re.match(r'^([a-zA-Z0-9_\-\@\.]+):\s*\n', text)
    if prefix_match:
        text_clean = text[prefix_match.end():]
    else:
        prefix_xml_match = re.match(r'^([a-zA-Z0-9_\-\@\.]+):\s*(?=<)', text)
        if prefix_xml_match:
            text_clean = text[prefix_xml_match.end():]
    unescaped = html.unescape(text_clean)
    return transform_xml_to_text(unescaped)


def find_voice_data(media_db_path, chat_name_id):
    """从 media db 中取该会话的语音数据 {local_id: voice_data}"""
    if not os.path.exists(media_db_path):
        logger.warning("媒体库不存在: %s", media_db_path)
        return {}
    conn = _smart_connect(media_db_path)
    cur = conn.cursor()
    cur.execute('SELECT local_id, create_time, voice_data FROM VoiceInfo WHERE chat_name_id=?', (chat_name_id,))
    out = {}
    for local_id, ct, vd in cur.fetchall():
        out[local_id] = (ct, vd)
    conn.close()
    logger.debug("媒体库读取语音数据 %d 条 (chat_name_id=%s)", len(out), chat_name_id)
    return out


def voice_to_text(voice_data):
    """SILK -> mp3 -> whisper 转文字"""
    import subprocess, tempfile
    idx = voice_data.find(b'#!SILK_V3')
    silk = voice_data[idx:] if idx >= 0 else voice_data
    logger.debug("语音数据长度 %d，SILK 头位置 %d", len(voice_data), idx)
    tmpdir = tempfile.mkdtemp()
    silkf = os.path.join(tmpdir, 'v.silk')
    pcmf = os.path.join(tmpdir, 'v.pcm')
    mp3f = os.path.join(tmpdir, 'v.mp3')
    with open(silkf, 'wb') as f:
        f.write(silk)
    try:
        import pilk
        pilk.decode(silkf, pcmf, 44100)
    except Exception as e:
        logger.warning("pilk 解码失败: %s", e)
        return None
    r = subprocess.run(['ffmpeg', '-y', '-f', 's16le', '-ar', '44100', '-ac', '1', '-i', pcmf, mp3f],
                       capture_output=True)
    if r.returncode != 0 or not os.path.exists(mp3f):
        logger.warning("ffmpeg 转 MP3 失败: %s", r.stderr.decode('utf-8', errors='ignore')[:200])
        return None
    import torch, warnings, whisper
    warnings.filterwarnings('ignore')
    torch.set_num_threads(4)
    model = whisper.load_model('base')
    model = model.to('cpu')
    res = model.transcribe(mp3f, language='zh')
    import shutil
    shutil.rmtree(tmpdir, ignore_errors=True)
    return res.get('text', '').strip()


def summarize_missing_dats(missing_collector):
    """汇总本地无 dat 文件的图片：以运行日期为"最近一天"，统计当天缺失的唯一图片数"""
    if not missing_collector:
        logger.info("图片本地缺失统计: 无（所有图片均有本地 dat 文件）")
        return
    first_by_md5 = {}
    for item in missing_collector:
        md5 = item['md5']
        if md5 not in first_by_md5:
            first_by_md5[md5] = item
        else:
            existing = first_by_md5[md5]['time'] or ''
            incoming = item['time'] or ''
            if incoming and (not existing or incoming < existing):
                first_by_md5[md5] = item
    unique = list(first_by_md5.values())
    today = datetime.date.today().strftime('%Y-%m-%d')
    today_count = sum(1 for e in unique if (e['time'] or '')[:10] == today)
    logger.info("图片本地缺失统计: 最近一天 %s 缺失 %d 张唯一图片（共 %d 张）",
                today, today_count, len(unique))


def main():
    parser = argparse.ArgumentParser(description='微信聊天记录导出 + 图片OCR/描述 + 语音转文字')
    parser.add_argument('contact', nargs='?', default=DEFAULT_CONTACT, help='联系人昵称/备注')
    parser.add_argument('--range', '-r', default=None,
                        help='时间范围，如 20260702-20260807、1d、1w、1m、1y、today、yesterday（默认全部）')
    args = parser.parse_args()
    if not args.contact:
        parser.error('请提供联系人昵称/备注（或设置 WECHAT_CONTACT 环境变量）')

    start_ts, end_ts = parse_time_range(args.range)
    logger.info("===== 开始导出：联系人=%s 范围=%s =====", args.contact,
                describe_range(args.range, start_ts, end_ts))
    logger.debug("配置: DB=%s", DB_PATH)
    logger.debug("配置: CONTACT_DB=%s", CONTACT_DB_PATH)
    logger.debug("配置: OCR=%s VLM=%s ASR=%s", ENABLE_OCR, ENABLE_VLM, ENABLE_ASR)
    logger.debug("配置: CACHE_DIR=%s", CACHE_DIR)

    # 定位会话
    logger.info("定位会话: %s", args.contact)
    table, username, display_name, _chat_hash = mt.locate_conversation(DB_PATH, CONTACT_DB_PATH, args.contact)
    logger.info("会话定位成功: %s (%s) -> 表 %s", display_name, username, table)

    sender_map = load_sender_map(DB_PATH, CONTACT_DB_PATH, self_name=display_name if username == SELF_WXID else SELF_NAME)
    # 强制将对端昵称设为目标联系人
    conn_m = _smart_connect(DB_PATH)
    cur_m = conn_m.cursor()
    cur_m.execute('SELECT rowid, user_name FROM Name2Id')
    for rowid, uname in cur_m.fetchall():
        if uname == username:
            sender_map[str(rowid)] = display_name
    logger.debug("发送者映射中目标联系人 rowid 已覆盖为显示名: %s", display_name)

    # 图片解析器
    img_resolver = mt.build_image_resolver(DB_PATH, HARDLINK_DB_PATH, ATTACH_ROOT) if ENABLE_OCR or ENABLE_VLM else {}
    logger.debug("图片解析器就绪，共 %d 条 md5 映射", len(img_resolver))

    # 语音（可选）
    voice_map = {}
    if ENABLE_ASR:
        # 注意：media db 的 Name2Id 编号与 message db 不同，需从 media db 自己取
        chat_name_id = mt.get_media_chat_name_id(MEDIA_DB_PATH, username)
        logger.debug("媒体库 chat_name_id=%s", chat_name_id)
        voice_map = find_voice_data(MEDIA_DB_PATH, chat_name_id) if chat_name_id else {}
        logger.info("语音消息 %d 条", len(voice_map))

    output_txt = f'./chat_history_{display_name}.txt'
    logger.debug("输出文件: %s", output_txt)

    # 增量状态（记录每个会话已处理到的 local_id，用于统计与日志）
    state = load_state()
    state.setdefault('conversations', {})
    conv_state = state['conversations'].setdefault(username, {})
    prev_max_local_id = conv_state.get('max_local_id', -1)
    logger.debug("增量状态: 上次 max_local_id=%s", prev_max_local_id)

    # 全量重写输出文件（纯文本拼接，快），但媒体处理走缓存 → 二次运行只算新消息媒体
    where = []
    params = []
    if start_ts is not None:
        where.append("create_time >= ?")
        params.append(start_ts)
    if end_ts is not None:
        where.append("create_time < ?")
        params.append(end_ts)
    where_sql = f" WHERE {' AND '.join(where)}" if where else ""
    sql = (f"SELECT local_id, real_sender_id, local_type, message_content, compress_content, create_time "
           f"FROM {table}{where_sql} ORDER BY create_time ASC")
    cur_m.execute(sql, params)
    rows = cur_m.fetchall()
    logger.info("读取消息 %d 条（表 %s）", len(rows), table)

    if prev_max_local_id >= 0:
        new_cnt = sum(1 for r in rows if r[0] > prev_max_local_id)
        logger.info("增量: 上次处理到 local_id=%s，本次新增 %d 条", prev_max_local_id, new_cnt)

    max_local_id = -1
    lines = []
    img_processed = 0
    voice_processed = 0
    missing_dats = []
    for idx, row in enumerate(rows):
        local_id, sender_id, local_type, mc, cc, create_time = row
        if local_id > max_local_id:
            max_local_id = local_id
        sender_name = sender_map.get(str(sender_id), f"未知用户({sender_id})")
        formatted_time = ""
        if create_time:
            try:
                dt = datetime.datetime.fromtimestamp(create_time)
                formatted_time = f"[{dt.strftime('%Y-%m-%d %H:%M:%S')}] "
            except Exception:
                pass
        final_content = process_message_content(mc if mc is not None else cc)

        # 图片消息处理
        if '<IMG' in final_content and (ENABLE_OCR or ENABLE_VLM):
            m = re.search(r'<IMG md5="([^"]*)" aeskey="([^"]*)"', final_content)
            md5 = m.group(1) if m else ''
            if md5:
                img_processed += 1
                msg_time = formatted_time.strip('[] ') or None
                annot = process_image_cached(md5, img_resolver, msg_time=msg_time,
                                             missing_collector=missing_dats)
                if annot:
                    if annot.startswith('解密失败'):
                        final_content = f'[图片]({annot})'
                    else:
                        final_content = f"[图片]({annot})"
                else:
                    final_content = '[图片]'

        # 语音消息处理
        elif '<VOICE' in final_content and ENABLE_ASR:
            voice_processed += 1
            final_content = process_voice_cached(local_id, voice_map)

        lines.append(f"{formatted_time}{sender_name}: {final_content}\n")

        if (idx + 1) % 1000 == 0 or idx + 1 == len(rows):
            logger.info("处理进度 %d/%d", idx + 1, len(rows))

    logger.info("媒体处理汇总: 图片 %d 条，语音 %d 条", img_processed, voice_processed)
    summarize_missing_dats(missing_dats)

    with open(output_txt, 'w', encoding='utf-8') as f:
        f.writelines(lines)

    # 更新状态（保证高水位单调递增，避免范围导出导致回退）
    conv_state['max_local_id'] = max(conv_state.get('max_local_id', -1), max_local_id)
    save_state(state)

    conn_m.close()
    actual_lines = sum(l.count('\n') for l in lines)
    logger.info("完成: 聊天记录已导出到 %s (共 %d 行)", output_txt, actual_lines)


if __name__ == '__main__':
    main()
