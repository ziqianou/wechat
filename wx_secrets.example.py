import os

# 真实微信数据目录（含 db_storage/ 的账号目录）
WX_BASE = '/path/to/xwechat_files/<wxid>_<pid>'
# 本人 wxid 与显示名
SELF_WXID = '<your_wxid>'
SELF_NAME = '<your_name>'

# 各数据库派生密钥（96 位十六进制：key(32B) || salt(16B)）
# 来源见 README「派生密钥格式与内存提取」
DB_KEYS = {
    'general.db': '<96-hex>',
    'contact.db': '<96-hex>',
    'message_0.db': '<96-hex>',
    'message_1.db': '<96-hex>',
    'media_0.db': '<96-hex>',
    'favorite.db': '<96-hex>',
    'emoticon.db': '<96-hex>',
    'session.db': '<96-hex>',
    'sns.db': '<96-hex>',
    'hardlink.db': '<96-hex>',
}

SNS_KEY = DB_KEYS['sns.db']
CONTACT_KEY = DB_KEYS['contact.db']

# 微信 4.0 图片 V2 dat 的固定 AES 密钥（所有账号一致）
IMAGE_AES_KEY = '35383831353565623631313961316330'

SNS_DB = os.path.join(WX_BASE, 'db_storage', 'sns', 'sns.db')
CONTACT_REAL = os.path.join(WX_BASE, 'db_storage', 'contact', 'contact.db')
