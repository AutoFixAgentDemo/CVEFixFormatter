import os
import re
import json
import sys
from typing import List, Tuple

import yaml
import typer
import rich
import tqdm
from loguru import logger
from utils import validate_path
from utils.mongo_interface import MongoInterface
from utils.providers.ollama_api import OllamaChatBase
from utils.extract_json import extract_json

mongo_handler = None
llm_handler = None


def find_cve_directories(repo_path: str) -> Tuple[List[str], int]:
    """
    Find all directories named as CVE numbers under the specific `data` directory structure.

    Args:
        repo_path (str): Root path to the Vulsrc repo.

    Returns:
        Tuple[List[str], int]: List of CVE directory paths and count.
    """
    cve_pattern = re.compile(r"^CVE-\d{4}-\d+$")
    data_path = os.path.join(repo_path, "data")
    cve_dirs = []

    # Ensure the `data` directory exists
    if not os.path.exists(data_path) or not os.path.isdir(data_path):
        raise typer.BadParameter(
            f"The 'data' directory does not exist in the given repo path: {
                data_path}"
        )

    # Traverse only subdirectories under `data`
    for sub_dir in os.listdir(data_path):
        sub_dir_path = os.path.join(data_path, sub_dir)
        if os.path.isdir(sub_dir_path):
            # Traverse subdirectories of sub_dir
            for inner_dir in os.listdir(sub_dir_path):
                inner_dir_path = os.path.join(sub_dir_path, inner_dir)
                if os.path.isdir(inner_dir_path) and cve_pattern.match(inner_dir):
                    cve_dirs.append(inner_dir_path)
    logger.info(
        f"Found {len(cve_dirs)} CVEs in the  target directory {repo_path}")
    return cve_dirs, len(cve_dirs)


def parse_cve_desc_json(cve_desc_path: str):
    """
    Parse the CVE description JSON file.

    Args:
        cve_desc_path (str): Path to the CVE description JSON file.

    Returns:
        dict: Parsed CVE description data.
    """
    with open(cve_desc_path, "r") as f:
        cve_raw = json.load(f)
    default_str = "N/A"
    processed_dict = dict()
    processed_dict["cve_number"] = cve_raw.get("cve_number", default_str)
    processed_dict["description"] = cve_raw.get("description", default_str)
    processed_dict["title"] = cve_raw.get("title", default_str)
    processed_dict["weaknesses"] = cve_raw.get("weaknesses", default_str)

    # Filled in after parsing the commit
    processed_dict["repo"] = default_str  # Should be freetype/freetype
    processed_dict["commit_message"] = default_str
    # Filled in after saving files to GridFS
    processed_dict["vulnerable_codes_id"] = list()
    processed_dict["patched_code_id"] = list()
    processed_dict["diff_id"] = list()
    # Filled in after asking to LLM
    processed_dict["functional_desc"] = default_str
    processed_dict["causes_of_the_vuln"] = default_str
    processed_dict["solution"] = default_str

    return processed_dict


def parse_CVE(cve_dir: str):
    """
    Parse the CVE data from the given directory.

    Args:
        cve_dir (str): Path to the CVE directory.

    Returns:
        dict: Parsed CVE data.
    """

    # if no subdir exists, pass
    if not os.path.exists(cve_dir) or not os.path.isdir(cve_dir):
        # Assume this directory has no valid commit
        logger.warning(f"No valid commit in {cve_dir}, skipping")
        return dict()
    else:
        # Check if the CVE has been parsed and saved to MongoDB
        cve_number = os.path.basename(cve_dir)
        if mongo_handler.find_one({"cve_number": cve_number}):
            logger.warning(f"Already parsed {cve_number}, skipping")
            return dict()

        def count_commits(directory):
            return sum(
                1
                for item in os.listdir(directory)
                if os.path.isdir(os.path.join(directory, item))
            )

        logger.info(
            f"Processing {cve_dir}, find {
                count_commits(cve_dir)} commits"
        )

        # if more than one subdir exists, pass
        # FIX: os.listdir is incorrect, should use os.scandir
        if count_commits(cve_dir) != 1:
            logger.warning(f"Multiple commits in {cve_dir}, skipping")
            logger.debug(
                f"Subdirectories: {
                    validate_path.list_all_dirs_in_path(cve_dir)}"
            )

            return dict()
        else:
            commit_dir = os.path.join(
                cve_dir, validate_path.list_all_dirs_in_path(cve_dir)[0]
            )

        # Parse json
        cve_desc_path = validate_path.get_unique_json_file_path(
            cve_dir
        )  # Should be CVE-xxxx.json
        cve_desc = parse_cve_desc_json(cve_desc_path)
        # Parse the commit and save the file to GridFS
        cve_desc = parse_commit(commit_dir, cve_desc)
        cve_desc = ask_llm(cve_desc)

        if cve_desc is None:
            logger.error(f"Failed to parse {
                         cve_desc_path}: max retry reached. Gracefully exiting...")
            return None

        # Save the parsed data to MongoDB
        try:
            mongo_handler.insert(cve_desc)
            logger.info(f"Inserted {cve_desc['cve_number']} to MongoDB")
        except Exception as e:
            logger.exception(f"Failed to insert {cve_desc['cve_number']}: {e}")

        # Convert _id to printable string
        cve_desc["_id"] = str(cve_desc["_id"])

        logger.debug(json.dumps(cve_desc, indent=4, ensure_ascii=False))
        return cve_desc


def parse_commit(commit_dir: str, cve_desc: dict):
    logger.info(f"Parsing commit in {commit_dir}")
    vuln_path = os.path.join(commit_dir, "vulnerable")
    patched_path = os.path.join(commit_dir, "patched")

    # Parse the commit description
    commit_desc_path = validate_path.get_unique_json_file_path(
        patched_path
    )  # Should be sha256.json
    logger.debug(f"Commit description path: {commit_desc_path}")
    with open(commit_desc_path, "r") as f:
        commit_desc = json.load(f)
    cve_desc["repo"] = (
        commit_desc.get("owner", "N/A") + "/" + commit_desc.get("repo", "N/A")
    )

    cve_desc["commit_message"] = commit_desc.get(
        "commit_massage", "N/A"
    )  # NOTE: A silly typo in vulnsrc

    # Get the vulnerable codes
    vuln_files = os.listdir(vuln_path)
    logger.debug(f"Vulnerable files: {vuln_files}")
    for vuln_file in vuln_files:
        vuln_file_path = os.path.join(vuln_path, vuln_file)
        logger.debug(f"Processing vulnerable file: {vuln_file_path}")
        # Save the file to GridFS

        try:
            id = mongo_handler.insert_file(vuln_file_path, vuln_file)
            logger.debug(
                f"Inserted vulnerable file to GridFS {
                    vuln_file} with id {id}"
            )
        except Exception as e:
            logger.error(f"Failed to insert file {vuln_file}: {e}")

        cve_desc["vulnerable_codes_id"].append(id)

    # Get the patched codes
    patched_files = os.listdir(patched_path)
    for patched_file in patched_files:
        # Exclude the commit info json file
        if patched_file == os.path.basename(commit_desc_path):
            continue
        # Exclude the .diff file
        if patched_file.endswith(".diff"):
            continue

        patched_file_path = os.path.join(patched_path, patched_file)
        logger.debug(f"Processing patched file: {patched_file}")
        # Save the file to GridFS
        try:
            id = mongo_handler.insert_file(patched_file_path, patched_file)
            logger.debug(
                f"Inserted patched file to GridFS {
                    patched_file} with id {id}"
            )
        except Exception as e:
            logger.error(f"Failed to insert file {patched_file}: {e}")

        cve_desc["patched_code_id"].append(id)

    # Get the diff file
    diff_files = os.listdir(patched_path)
    for diff_file in diff_files:
        if diff_file.endswith(".diff"):
            diff_file_path = os.path.join(patched_path, diff_file)
            logger.debug(f"Processing diff file: {diff_file_path}")
            # Save the file to GridFS
            try:
                id = mongo_handler.insert_file(diff_file_path, diff_file)
                logger.debug(
                    f"Inserted diff file to GridFS {
                        diff_file} with id {id}"
                )
            except Exception as e:
                logger.error(f"Failed to insert file {diff_file}: {e}")
            cve_desc["diff_id"].append(id)

    return cve_desc


def ask_llm(cve_desc: dict) -> dict:
    """
    To ask LLM for the functional description, causes of the vulnerability, and solution.

    Args:
        cve_desc (dict): The parsed CVE description data. Shold be filled except for the LLM-based info.

    Returns:
        dict: The updated CVE description data.
    """
    PROMPT_TEMPLATE_ABSTRACT = """
    # Prompt Template

    Please analyze the following CVE (Common Vulnerabilities and Exposures) description provided in JSON format. Using both the provided information and your prior knowledge, thoroughly answer the following questions using the specific symbols provided in the code snippet:

    1. **Functional Description of Each Function Involved in the Diff:**
    - For **each function** mentioned in the diff, provide a detailed description of its **purpose**, how it operates within the codebase, and its role in the overall system.

    2. **Causes of the Vulnerability:**
    - Explain in detail the root causes of the vulnerability. Discuss any flaws in logic, validation errors, improper handling of inputs, or other coding issues that led to the vulnerability.

    3. **Description of How the Patch Fixes the Vulnerability:**
    - Describe precisely how the patch addresses and resolves the vulnerability. Explain the specific changes made to the code and why these changes effectively mitigate the issue.
    **CVE Description:**
    ```json
    {cve_desc}
    ```
    **Original code:**
    {vulnerable_code}

    **Patched code:**
    {patched_code}

    **Diff:**
    {diff}

    **Output Format: **

    Please present your answers in the following JSON format without modifying the keys and any other unnecessary contents. You may provide additional information in the values as needed.:
    ```json
    {{
        \"general_purpose\":{{
            \"function_name1\": "The general purpose in few sentences of function_name1.",
            \"function_name2\": "The general purpose in few sentences of function_name2."
        }}
        \"implement_description\": {{
            \"function_name1\": "Detailed implement description step by step in function_name1.",
            \"function_name2\": "Detailed implement description step by step in function_name2."
            // Add more functions as needed.
        }},
        \"causes\": "Comprehensive explanation of the causes of the vulnerability.",
        \"solution\": "Detailed description of how the patch fixes the vulnerability."
    }}
    ```
    """
    retry_cnt = 0
    MAX_RETRY = 3

    # Retrieve the files from GridFS using id in the cve_desc
    # Fix: wrong method calling
    # Fix: cve_desc["vulnerable_codes_id"] is a list and may contains multiple files.
    # NOTE: vuln_files should be a list of file pointers
    try:
        vuln_files = patched_files = diff_files = []
        for vuln_id in cve_desc["vulnerable_codes_id"]:
            vuln_files.append(mongo_handler.find_file_by_id(vuln_id))
        for patched_id in cve_desc["patched_code_id"]:
            patched_files.append(mongo_handler.find_file_by_id(patched_id))
        for diff_id in cve_desc["diff_id"]:
            diff_files.append(mongo_handler.find_file_by_id(diff_id))

        # logger.debug(f"{vuln_files=},{patched_files=},{diff_files=}")
        # Ensure the files are not None
        assert vuln_files and patched_files and diff_files

    except Exception as e:
        logger.error(f"Failed to retrieve files from GridFS: {e}")
        return None

    # Get the content of the files
    vulnerable_code = patched_code = diff = ""
    for file in vuln_files:
        # Get the filename
        filename = file.filename
        vulnerable_code += f"**{filename}**\n" + \
            file.read().decode("utf-8") + "\n\n"
    for file in patched_files:
        # Get the filename
        filename = file.filename
        patched_code += f"**{filename}**\n" + \
            file.read().decode("utf-8") + "\n\n"
    for file in diff_files:
        # Get the filename
        filename = file.filename
        diff += f"**{filename}**\n" + file.read().decode("utf-8") + "\n\n"

    # Fill in the prompt template

    try:
        prompt = PROMPT_TEMPLATE_ABSTRACT.format(
            cve_desc=json.dumps(cve_desc, indent=4, ensure_ascii=False).replace(
                '"', '\\"'
            ),
            vulnerable_code=vulnerable_code,
            patched_code=patched_code,
            diff=diff,
        )
    except KeyError as e:
        logger.error(f"Failed to fill in the prompt template: {e}")
    while retry_cnt < MAX_RETRY:
        resp_raw = llm_handler.send_message(prompt)
        try:
            resp_dict = json.loads(resp_raw)
        except json.JSONDecodeError as e:
            logger.warning(
                f"Failed to parse JSON response directly from LLM:{e}."
            )
            resp_dict = extract_json(resp_raw)
        logger.debug(f"Response from LLM in 1st stage: {resp_dict}")
        # Validity check if the response is a dict and keys are correct
        if resp_dict is None:
            logger.warning(
                f"Invalid response from LLM: {
                    resp_dict}. Retry...{retry_cnt}"
            )
            retry_cnt += 1
            continue
        if not all(
            key in resp_dict.keys()
            for key in ["general_purpose", "implement_description", "causes", "solution"]
        ):
            logger.warning(
                f"Invalid response from LLM: Dismatched key {
                    resp_dict}. Retry...{retry_cnt}"
            )
            retry_cnt += 1

            continue
        # Get the content in resp_dict
        general_purpose = resp_dict["general_purpose"]
        functional_desc = resp_dict["implement_description"]
        causes = resp_dict["causes"]
        solution = resp_dict["solution"]
        break
    if retry_cnt == MAX_RETRY:
        logger.warning(
            f"Failed to get valid response from LLM in 1st stage. Exiting...")
        return None

    # The second stage of asking LLM
    PROMPT_TEMPLATE_GENERAL = """
        With the detailed vulnerability knowledge extracted from the previous stage, your task is to abstract and generalize this knowledge to enhance its applicability across different scenarios. Based on this information, please address the following WITHOUT referencing the original CVE description or the sepcific name of variables, functions, or classes in the value:
        
        1. **Function Summaries:**
        - Summarize the purpose and functionality of each function involved in the diff concisely and without using specific symbols or extra explanations.

        2. **Generalizable Vulnerability Behavior:**
        - Summarize the specific behavior of the code that caused the vulnerability, ensuring your description is generalized but retains the technical specificity of the root issue.

        3. **Specific Solution to Fix the Vulnerability:**
        - Provide a summary of the specific solution implemented in the patch to address the vulnerability WITHOUT referencing the original CVE description or the sepcific name of variables, functions, or classes.

        **Abstract Purpose Description:**
        {general_purpose}

        **Implement details:**
        {functional_desc}
        
        **Abstract Causes:**
        {causes}

        **Abstract Solution:**
        {solution}

        **Output Format:**

        Provide your answers in the following JSON structure:

        ```json
        {{
            "functional_description": {{
                "function_name1": "Summary of function_name1",
                //replace the key to the real function name
                "function_name2": "Summary of function_name2"
                // Add more functions as needed
            }},
            "causes": "Generalized explanation of the code behavior that leads to the vulnerability.",
            "solution": "Specific explanation of how the patch fixes the vulnerability."
        }}
        ```
        """
    prompt = PROMPT_TEMPLATE_GENERAL.format(
        general_purpose=general_purpose,
        functional_desc=functional_desc,
        causes=causes,
        solution=solution,
    )
    retry_cnt = 0
    while retry_cnt < MAX_RETRY:
        resp_raw = llm_handler.send_message(prompt)
        try:
            resp_dict = json.loads(resp_raw)
        except json.JSONDecodeError as e:
            logger.warning(
                f"Failed to parse JSON response directly from LLM:{e}."
            )
            resp_dict = extract_json(resp_raw)
        logger.debug(f"Response from LLM in 1st stage: {resp_dict}")
        # Validity check if the response is a dict and keys are correct
        if resp_dict is None:
            logger.warning(
                f"Invalid response from LLM: {
                    resp_dict}. Retry...{retry_cnt}"
            )
            retry_cnt += 1
            continue
        if not all(
            key in resp_dict.keys()
            for key in ["functional_description", "causes", "solution"]
        ):
            logger.warning(
                f"Invalid response from LLM: Dismatched key {
                    resp_dict}. Retry...{retry_cnt}"
            )
            retry_cnt += 1

            continue
        # Get the content in resp_dict
        functional_desc = resp_dict["functional_description"]
        causes = resp_dict["causes"]
        solution = resp_dict["solution"]
        break
    if retry_cnt == MAX_RETRY:
        logger.error(
            f"Failed to get valid response from LLM in 2nd stage. Exiting...")
        return None

    # Merge the results to CVE description
    cve_desc["general_purpose"] = general_purpose
    cve_desc["functional_desc"] = functional_desc
    cve_desc["causes_of_the_vuln"] = causes
    cve_desc["solution"] = solution
    return cve_desc


def main(
    repo_path: str = typer.Option(
        ...,
        callback=validate_path.validate_path,
        help="The path of Vulsrc repo's root path",
    ),
    mongo_host: str = typer.Option(
        "127.0.0.1", help="The host address of the mongodb"),
    mongo_port: int = typer.Option(27017, help="The port of the mongodb port"),
):

    logger.info(f"{repo_path=},{mongo_host=},{mongo_port=}")
    # Initialize the MongoDB connection
    global mongo_handler
    mongo_handler = MongoInterface(mongo_host, mongo_port)

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
    global llm_handler
    llm_handler = OllamaChatBase(api_endpoints, model)

    # 获取该目录下所有的CVE信息
    cve_dirs, dirs_cnt = find_cve_directories(repo_path=repo_path)
    logger.info(f"Found {dirs_cnt} CVEs in the target directory {repo_path}")

    # Main Loop. 遍历所有的CVE目录并解析其中的数据
    for cve_dir in tqdm.tqdm(cve_dirs, desc="Parsing CVEs", unit="CVE"):
        logger.info(f"Parsing {cve_dir}")
        # Return a dict with file and LLM-based info filled
        parse_CVE(cve_dir)


if __name__ == "__main__":
    typer.run(main)


# Unit test and parse single CVE
# if __name__ == "__main__":
#     logger.remove()
#     logger.add(sys.stderr, level="DEBUG")
#     # Initialize the MongoDB connection

#     mongo_handler = MongoInterface("127.0.0.1", 27017)
#     cve_dir = "../VulnCodeCollector/data/boundary/CVE-2018-10940"
#     parse_CVE(cve_dir)
