import os
import re
import json
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
            f"The 'data' directory does not exist in the given repo path: {data_path}")

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
    processed_dict["commit_massage"] = default_str
    # Filled in after saving files to GridFS
    processed_dict["Vulnerable_codes_id"] = list()
    processed_dict["patched_code_id"] = list()

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
        logger.warning(
            f"No valid commit in {cve_dir}, skipping")
        return dict()
    else:
        logger.info(f"Processing {cve_dir}, find {
                    len(os.listdir(cve_dir))} commits")
        # if more than one subdir exists, pass
        if len(os.listdir(cve_dir)) != 1:
            logger.warning(
                f"Multiple commits in {cve_dir}, skipping")
            return dict()
        else:
            commit_dir = os.path.join(cve_dir, os.listdir(cve_dir)[0])

            # Parse json
            cve_desc_path = validate_path.get_unique_json_file_path(
                cve_dir)  # Should be CVE-xxxx.json
            cve_desc = parse_cve_desc_json(cve_desc_path)

            # Parse the commit and save the file to GridFS


def main(repo_path: str = typer.Option(..., callback=validate_path.validate_path, help="The path of Vulsrc repo's root path"), mongo_host: str = typer.Option("127.0.0.1", help="The host address of the mongodb"), mongo_port: int = typer.Option(27017, help="The port of the mongodb port")):
    # console = rich.console()
    logger.info(f"{repo_path=},{mongo_host=},{mongo_port=}")

    # 获取该目录下所有的CVE信息
    cve_dirs, dirs_cnt = find_cve_directories(repo_path=repo_path)

    # Main Loop. 遍历所有的CVE目录并解析其中的数据
    for cve_dir in tqdm.tqdm(cve_dirs, desc="Parsing CVEs", unit="CVE"):
        logger.info(f"Parsing {cve_dir}")
        # Return a dict with file and LLM-based info unfilled
        parse_CVE(cve_dir)


if __name__ == "__main__":
    typer.run(main)
