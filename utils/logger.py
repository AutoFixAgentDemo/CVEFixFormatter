
# logger.py
from loguru import logger
import sys

# 初始化全局日志器
logger.remove()  # 移除默认日志器
# 默认级别为 INFO
logger.add(
    sys.stdout, format="{time:YYYY-MM-DD HH:mm:ss} [{level}]:{message}", level="INFO")


def set_log_level(verbose: bool):
    logger.remove()  # 移除现有的日志器
    log_level = "DEBUG" if verbose else "INFO"
    logger.add(
        sys.stdout, format="{time:YYYY-MM-DD HH:mm:ss} [{level}]:{message}", level=log_level)
    logger.info(f"Log level set to {log_level}")
