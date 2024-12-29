import json
import os
import re
from typing import List, Tuple

import tqdm
import typer
import yaml
from loguru import logger

from models.desc import CVEDescription
from models.llm_resp import FunctionInfoList, InitSecInfo
from models.meta import CVEMeta, PatchMeta
from utils import validate_path
from utils.mongo_interface import MongoInterface
from utils.providers.ollama_api import OllamaChatBase
from utils.send_req_to_llm import send_req_to_llm

mongo_handler = None
llm_handler = None

# Count the commits for this CVE. Exclude it if more than one.


def count_commits(directory):
    return sum(
        1
        for item in os.listdir(directory)
        if os.path.isdir(os.path.join(directory, item))
    )


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


def parse_cve_desc_json(cve_desc_path: str) -> CVEDescription:
    """
    Parse the CVE description JSON file.

    Args:
        cve_desc_path (str): Path to the CVE description JSON file.

    Returns:
        CVEDescription: Parsed CVE description data as a CVEDescription instance.
    """
    with open(cve_desc_path, "r") as f:
        cve_raw = json.load(f)

    # Initialize the CVEDescription object with values from the JSON
    # NOTE: to prevent empty value from being None
    def value_getter(key, default_val): return cve_raw.get(
        key, default_val) if cve_raw.get(key) else default_val
    cve_meta = CVEMeta(
        cve_number=value_getter("cve_number", "N/A"),
        description=value_getter("description", "N/A"),
        title=value_getter("title", "N/A"),
        weaknesses=value_getter("weaknesses", list()),
    )

    cve_description = CVEDescription(cve_meta=cve_meta)
    # The remaining fields (repo, commit_message, vulnerable_codes_id, etc.)
    # are already initialized with their default values in the dataclass definition.
    return cve_description


def parse_CVE(cve_dir: str):
    """
    Parse the CVE data from the given directory.

    Args:
        cve_dir (str): Path to the CVE directory.

    Returns:
        None
    """

    # if no subdir exists, pass
    if not os.path.exists(cve_dir) or not os.path.isdir(cve_dir):
        # Assume this directory has no valid commit
        logger.warning(f"No valid commit in {cve_dir}, skipping")
        return None
    else:
        # Check if the CVE has been parsed and saved to MongoDB
        cve_number = os.path.basename(cve_dir)
        if mongo_handler.find_one({"cve_meta.cve_number": cve_number}):
            logger.warning(f"Already parsed {cve_number}, skipping")
            return None

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

        return None
    else:
        commit_dir = os.path.join(
            cve_dir, validate_path.list_all_dirs_in_path(cve_dir)[0]
        )

        # Parse json
        cve_desc_path = validate_path.get_unique_json_file_path(
            cve_dir
        )  # Should be CVE-xxxx.json

        # NOTE: start using the base model here
        cve_desc = parse_cve_desc_json(cve_desc_path)
        # Parse the commit and save the file to GridFS
        cve_desc = parse_commit(commit_dir, cve_desc)
        cve_desc = ask_llm(cve_desc)

        if cve_desc is None:
            logger.error(
                f"Failed to parse {
                    cve_desc_path}: Parse failed. Gracefully exiting..."
            )
            return None

        # Save the parsed data to MongoDB
        # Convert the dataclass object to a dictionary
        cve_desc_ready_to_insert = cve_desc.model_dump()
        try:
            mongo_handler.insert(cve_desc_ready_to_insert)
            logger.info(f"Inserted {cve_desc.cve_meta.cve_number} to MongoDB")
        except Exception as e:
            logger.exception(f"Failed to insert {
                             cve_desc.cve_meta.cve_number}: {e}")

        # Convert _id to printable string
        # cve_desc._id = str(result.inserted_id)
        # cve_desc.id = str(cve_desc.id)
        logger.debug(f"Inserted data: {cve_desc_ready_to_insert} with id {
                     str(cve_desc_ready_to_insert['_id'])}")
        return cve_desc


def parse_commit(commit_dir: str, cve_desc: CVEDescription) -> CVEDescription:
    """
    Parse the patch info and fill in cve_desc
    """
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

    repo = commit_desc.get("owner", "N/A") + "/" + \
        commit_desc.get("repo", "N/A")

    # NOTE: A silly typo in vulnsrc
    commit_message = commit_desc.get("commit_massage", "N/A")

    # Initialize the PatchMeta object with values from the JSON
    patch_meta = PatchMeta(
        commit_sha=commit_desc.get("commit_sha", "N/A"),
        commit_message=commit_message,
        repo=repo,
    )
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
            patch_meta.vulnerable_codes_id.append(id)
        except Exception as e:
            logger.error(f"Failed to insert file {vuln_file}: {e}")

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
            patch_meta.patched_code_id.append(id)
        except Exception as e:
            logger.error(f"Failed to insert file {patched_file}: {e}")

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
                patch_meta.diff_id.append(id)
            except Exception as e:
                logger.error(f"Failed to insert file {diff_file}: {e}")

    # Merge the PatchMeta object to the CVEDescription object
    cve_desc.cve_meta.patch_meta = patch_meta
    return cve_desc


def ask_llm(cve_desc: CVEDescription) -> CVEDescription:
    """
    To ask LLM for the functional description, causes of the vulnerability, and solution.

    Args:
        cve_desc (CVEDescription): The parsed CVE description data. Be filled except for the LLM-based info.
    Returns:
        dict: The updated CVE description data.
    """
    # Prepare phase
    try:
        vuln_files = patched_files = diff_files = []
        for vuln_id in cve_desc.cve_meta.patch_meta.vulnerable_codes_id:
            vuln_files.append(mongo_handler.find_file_by_id(vuln_id))
        for patched_id in cve_desc.cve_meta.patch_meta.patched_code_id:
            patched_files.append(mongo_handler.find_file_by_id(patched_id))
        for diff_id in cve_desc.cve_meta.patch_meta.diff_id:
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

    # Do functional extract
    from prompts.func_extract import FUNC_EXTRACT_PROMPT_TEMPLATE

    prompt = FUNC_EXTRACT_PROMPT_TEMPLATE.format(
        vuln_source=vulnerable_code, patched_source=patched_code, diff_source=diff
    )
    func_desc = send_req_to_llm(prompt=prompt, expected_model=FunctionInfoList)
    if func_desc:
        cve_desc.desc.funcs_desc = func_desc
        logger.debug(
            f"Functional extraction finished:{
                func_desc.model_dump_json()}"
        )
    else:
        logger.warning(
            f"Failed to extact functional desc for {
                cve_desc.cve_meta.cve_number}"
        )
        return None

    # Do Sec extract
    from prompts.sec_extract import INIT_SEC_EXTRACTION

    prompt = INIT_SEC_EXTRACTION.format(
        cve_number=cve_desc.cve_meta.cve_number,
        title=cve_desc.cve_meta.title,
        description=cve_desc.cve_meta.description,
        weaknesses=(
            ",".join(cve_desc.cve_meta.weaknesses)
            if cve_desc.cve_meta.weaknesses
            else "N/A"
        ),
        commit_message=cve_desc.cve_meta.patch_meta.commit_message,
        repo=cve_desc.cve_meta.patch_meta.repo,
        vuln_source=vulnerable_code,
        patched_source=patched_code,
        diff_source=diff,
    )
    sec_desc = send_req_to_llm(prompt=prompt, expected_model=InitSecInfo)
    if sec_desc:
        cve_desc.desc.sec_desc = sec_desc
    else:
        logger.warning(
            f"Failed to extract sec desc for {
                cve_desc.cve_meta.cve_number} "
        )
        return None

    # Finish extraction
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
        parse_CVE(cve_dir)


if __name__ == "__main__":
    typer.run(main)
