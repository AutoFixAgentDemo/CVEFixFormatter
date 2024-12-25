"""
Provide an universal interface to ask a language model for the expected response.
"""

from loguru import logger
from .providers.ollama_api import OllamaChatBase
from .extract_json import extract_json
import json
import yaml
import pydantic
import re


def send_req_to_llm(
    prompt: str, expected_model: pydantic.BaseModel
) -> pydantic.BaseModel:
    """
    Ask a language model for the expected response.

    Args:
    prompt: str
        The formatted prompt to ask the language model.
    expected_model:
        The exected dataclass model to parse the response.

    Returns:
        pydantic.BaseModel: The parsed response in the expected model. None if failed.
    """
    # Load and parse LLM providers info from config.yaml
    with open("config.yaml", "r") as file:
        config = yaml.safe_load(file)

    logger.debug(f"Loaded config: {config}")
    try:
        api_endpoints = config["llm"]["base_url"]
        model = config["llm"]["model"]
    except KeyError as e:
        logger.error(f"Failed to load LLM config: {e}")
        return
    logger.info(f"LLM API info loaded: {api_endpoints=}, {model=}")

    # Init LLM interface
    llm_handler = OllamaChatBase(api_endpoints, model)

    retry_cnt = 0
    MAX_RETRY = 3
    while retry_cnt < MAX_RETRY:
        resp_raw = llm_handler.send_message(prompt)
        # Extract JSON from the response

        if resp_parsed := extract_json(resp_raw):
            # Validate the response with the expected model
            if resp_obj := validate_resp(resp_parsed, expected_model):
                return resp_obj
        retry_cnt += 1
        logger.warning(
            f"Failed to parse response from LLM. Retry {retry_cnt}/{MAX_RETRY}. Response: {resp_raw}"
        )
    logger.warning(f"Failed to get valid response from LLM. Max retry reached.")
    return None
    # FIXME:大模型难以返回正确的类型，考虑把返回的字符串再送给大模型让大模型重新解析并返回正确的数据模型


def validate_resp(resp_dict: dict, expected_model: pydantic.BaseModel):
    """
    Validate the response from LLM with the expected model.

    Args:
    resp_dict: dict
        The response from LLM to validate.
    expected_model:
        The exected pydantic model to parse the response.

    Returns:
        pydantic.BaseModel:The parsed response in the expected model. None if failed.
    """
    # Check if the response is a dict
    """if not isinstance(resp_dict, dict):
        logger.warning(
            f"Invalid response from LLM: {resp_dict}. Expected a dict.")
        return None"""

    """# Check if the response has the expected keys
    expected_keys = expected_model.__dataclass_fields__.keys()
    if not set(expected_keys).issubset(resp_dict.keys()):
        logger.warning(
            f"Invalid response from LLM: {resp_dict}. Expected keys: {expected_keys}"
        )
        return None
"""
    # Parse the response with the expected model
    try:
        resp_obj = expected_model(**resp_dict)
    except TypeError as e:
        logger.warning(f"Failed to parse response from LLM with expected model: {e}")
        return None

    return resp_obj


def extract_json(input_string):
    """
    Try to parse the json dict from the LLM"""

    def try_parse_json(s):
        try:
            return json.loads(s)
        except json.JSONDecodeError:
            return None

    # 尝试直接解析输入字符串
    result = try_parse_json(input_string)
    if result is not None and type(result) == dict:
        return result

    # 尝试将输入字符串视为被代码块包裹的JSON进行解析
    # 假设代码块使用三个反引号（```）包裹
    code_fence_start = input_string.find("```")
    if code_fence_start != -1:
        code_fence_end = input_string.find("```", code_fence_start + 3)
        if code_fence_end != -1:
            json_str = input_string[code_fence_start + 3 : code_fence_end].strip()
            result = try_parse_json(json_str)
            if result is not None:
                return result

    # 尝试匹配```json```模式
    codefence_pattern = r"```json\n(.*?)\n```"
    match = re.search(codefence_pattern, input_string, re.DOTALL)

    if not match:
        # print("No JSON found inside codefences.")
        return None

    json_str = match.group(1).strip()

    try:
        # Parse and validate the JSON
        parsed_json = json.loads(json_str)
        # print("Valid JSON extracted and parsed successfully.")
        return parsed_json
    except json.JSONDecodeError as e:
        # print(f"Invalid JSON: {e}")
        return None

    # 如果所有尝试都失败，返回空字典
    return None
