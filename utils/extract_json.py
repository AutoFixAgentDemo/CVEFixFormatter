"""
To extract json string from code fence"""
import re
import json
from utils.logger import logger, set_log_level


def extract_json(input_text):
    """
    Match and extract json string from the resp of llm"""
    match = re.search(r"```(?:json)?\n(.*?)\n```", input_text, re.DOTALL)
    if match:
        json_code = match.group(1)
        try:
            # 解析 JSON
            parsed_json = json.loads(json_code)
            return parsed_json
        except json.JSONDecodeError as e:
            logger.warning("Wrong JSON format", e)
            return None
    else:
        logger.warning("No JSON found: ", input_text)
    return None
