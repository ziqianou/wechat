"""标准化日志配置模块

统一日志格式与级别，供 main.py / media_tools.py 等模块复用。
级别可通过环境变量 WECHAT_LOG_LEVEL 覆盖（DEBUG/INFO/WARNING/ERROR）。
"""
import logging
import os
import sys

LOG_FORMAT = (
    "%(asctime)s | %(levelname)-7s | %(name)-24s | "
    "%(funcName)s:%(lineno)-4d | %(message)s"
)
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

_configured = False


def setup_logging(level=None, stream=None):
    """初始化根 logger。可重复调用，只会生效一次。"""
    global _configured
    if _configured:
        return
    if level is None:
        level = os.environ.get("WECHAT_LOG_LEVEL", "INFO").upper()
    numeric = getattr(logging, level, None)
    if not isinstance(numeric, int):
        numeric = logging.INFO
    handler = logging.StreamHandler(stream or sys.stdout)
    handler.setFormatter(logging.Formatter(LOG_FORMAT, datefmt=DATE_FORMAT))
    root = logging.getLogger()
    root.setLevel(numeric)
    root.addHandler(handler)
    _configured = True
    return logging.getLogger(__name__)


def get_logger(name):
    """获取命名 logger（自动完成初始化）。"""
    setup_logging()
    return logging.getLogger(name)
