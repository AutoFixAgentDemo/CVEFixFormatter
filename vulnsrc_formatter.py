import os
import re
import json
import sys
from typing import List, Tuple

import typer
import rich
import tqdm
from loguru import logger
from utils import validate_path


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
            f"The 'data' directory does not exist in the given repo path: {data_path}"
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
    logger.info(f"Found {len(cve_dirs)} CVEs in the  target directory {repo_path}")
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
    processed_dict["commit_massage"] = default_str
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
        if count_commits(cve_dir) != 1:
            logger.warning(f"Multiple commits in {cve_dir}, skipping")
            logger.debug(f"Subdirectories: {os.listdir(cve_dir)}")
            return dict()
        else:
            commit_dir = os.path.join(cve_dir, os.listdir(cve_dir)[0])

        # Parse json
        cve_desc_path = validate_path.get_unique_json_file_path(
            cve_dir
        )  # Should be CVE-xxxx.json
        cve_desc = parse_cve_desc_json(cve_desc_path)
        logger.debug(json.dumps(cve_desc, indent=4, ensure_ascii=False))
        # Parse the commit and save the file to GridFS
        parse_commit(commit_dir, cve_desc)


def parse_commit(commit_dir: str, cve_desc: dict):
    logger.info(f"Parsing commit in {commit_dir}")
    vuln_path = os.path.join(commit_dir, "vulnerable")
    patched_path = os.path.join(commit_dir, "patched")

    # Parse the commit description
    commit_desc_path = validate_path.get_unique_json_file_path(
        commit_dir
    )  # Should be sha256.json
    logger.debug(f"Commit description path: {commit_desc_path}")
    with open(commit_desc_path, "r") as f:
        commit_desc = json.load(f)
    cve_desc["repo"] = (
        commit_desc.get("owner", "N/A") + "/" + commit_desc.get("repo", "N/A")
    )
    cve_desc["commit_massage"] = commit_desc.get("commit_message", "N/A")

    # Get the vulnerable codes
    vuln_files = os.listdir(vuln_path)
    logger.debug(f"Vulnerable files: {vuln_files}")
    for vuln_file in vuln_files:
        vuln_file_path = os.path.join(vuln_path, vuln_file)
        logger.debug(f"Processing vulnerable file: {vuln_file_path}")
        # Save the file to GridFS
        # Use placeholder for now
        cve_desc["vulnerable_codes_id"].append(vuln_file)

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
        logger.debug(f"Processing patched file: {patched_file_path}")
        # Save the file to GridFS
        # Use placeholder for now
        cve_desc["patched_code_id"].append(patched_file)

    # Get the diff file
    diff_files = os.listdir(commit_dir)
    for diff_file in diff_files:
        if diff_file.endswith(".diff"):
            diff_file_path = os.path.join(commit_dir, diff_file)
            logger.debug(f"Processing diff file: {diff_file_path}")
            # Save the file to GridFS
            # Use placeholder for now
            cve_desc["diff_id"].append(diff_file)

    return cve_desc


def main(
    repo_path: str = typer.Option(
        ...,
        callback=validate_path.validate_path,
        help="The path of Vulsrc repo's root path",
    ),
    mongo_host: str = typer.Option("127.0.0.1", help="The host address of the mongodb"),
    mongo_port: int = typer.Option(27017, help="The port of the mongodb port"),
):
    # console = rich.console()
    logger.info(f"{repo_path=},{mongo_host=},{mongo_port=}")

    # 获取该目录下所有的CVE信息
    cve_dirs, dirs_cnt = find_cve_directories(repo_path=repo_path)

    # Main Loop. 遍历所有的CVE目录并解析其中的数据
    for cve_dir in tqdm.tqdm(cve_dirs, desc="Parsing CVEs", unit="CVE"):
        logger.info(f"Parsing {cve_dir}")
        # Return a dict with file and LLM-based info unfilled
        parse_CVE(cve_dir)


"""
if __name__ == "__main__":
    typer.run(main)
"""

# Test and parse single CVE
if __name__ == "__main__":
    logger.remove()
    logger.add(sys.stderr, level="DEBUG")
    cve_dir = "../VulnCodeCollector/data/boundary/CVE-2018-10940"
    parse_CVE(cve_dir)
