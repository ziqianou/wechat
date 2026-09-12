"""时间范围表达式解析（类 logwatch --range 语法）。

支持语法:
    20260702               单个日期：当天 00:00:00 ~ 23:59:59
    20260702-20260807      日期区间：含首尾两天
    today / yesterday      今天（从零点起） / 昨天一整天
    1d / 3d                最近 N 天
    1w / 2w                最近 N 周
    1m / 3m                最近 N 月
    1y / 2y                最近 N 年
    all / ''               不过滤（全部）

过滤语义: start_ts <= create_time < end_ts（end_ts 为 None 表示不设上限）。
"""
import re
import calendar
import datetime


def _days_in_month(year, month):
    return calendar.monthrange(year, month)[1]


def _parse_date(yyyymmdd):
    return datetime.datetime.strptime(yyyymmdd, '%Y%m%d')


def _add_months(dt, months):
    m = dt.month - 1 + months
    y = dt.year + m // 12
    m = m % 12 + 1
    day = min(dt.day, _days_in_month(y, m))
    return dt.replace(year=y, month=m, day=day)


def _add_years(dt, years):
    y = dt.year + years
    day = min(dt.day, _days_in_month(y, dt.month))
    return dt.replace(year=y, day=day)


def _ts(dt):
    return int(dt.timestamp())


def parse_time_range(expr):
    """解析时间范围表达式。

    Returns:
        (start_ts, end_ts): Unix 秒时间戳；None 表示不设边界。
    Raises:
        ValueError: 表达式无法解析。
    """
    if expr is None:
        return None, None
    expr = expr.strip()
    if not expr or expr.lower() in ('all', '*'):
        return None, None

    now = datetime.datetime.now()

    m = re.fullmatch(r'(\d{8})-(\d{8})', expr)
    if m:
        start = _parse_date(m.group(1))
        end = _parse_date(m.group(2)) + datetime.timedelta(days=1)
        return _ts(start), _ts(end)

    m = re.fullmatch(r'(\d{8})', expr)
    if m:
        start = _parse_date(m.group(1))
        end = start + datetime.timedelta(days=1)
        return _ts(start), _ts(end)

    lower = expr.lower()
    if lower == 'today':
        start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        return _ts(start), _ts(now) + 1
    if lower == 'yesterday':
        today = now.replace(hour=0, minute=0, second=0, microsecond=0)
        start = today - datetime.timedelta(days=1)
        return _ts(start), _ts(today)

    m = re.fullmatch(r'(\d+)([dwmy])', lower)
    if m:
        n = int(m.group(1))
        unit = m.group(2)
        if unit == 'd':
            start = now - datetime.timedelta(days=n)
        elif unit == 'w':
            start = now - datetime.timedelta(weeks=n)
        elif unit == 'm':
            start = _add_months(now, -n)
        elif unit == 'y':
            start = _add_years(now, -n)
        return _ts(start), _ts(now) + 1

    raise ValueError(f"无法解析时间范围表达式: {expr!r}（支持 20260702、20260702-20260807、today、yesterday、1d/1w/1m/1y）")


def describe(expr, start_ts, end_ts):
    """返回人类可读的范围描述，供日志/输出使用。"""
    fmt = '%Y-%m-%d %H:%M:%S'
    if start_ts is None and end_ts is None:
        return f"{expr or 'all'} (全部消息)"
    start_s = datetime.datetime.fromtimestamp(start_ts).strftime(fmt) if start_ts is not None else '不限'
    end_s = datetime.datetime.fromtimestamp(end_ts - 1).strftime(fmt) if end_ts is not None else '不限'
    return f"{expr} ({start_s} ~ {end_s})"
