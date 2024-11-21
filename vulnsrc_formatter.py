import typer
import rich
import os
from utils import validate_path
from loguru import logger
from typing import List, Tuple
import re

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
        raise typer.BadParameter(f"The 'data' directory does not exist in the given repo path: {data_path}")

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

def main(repo_path:str=typer.Option(...,callback=validate_path.validate_path,help="The path of Vulsrc repo's root path"),mongo_host:str=typer.Option(...,help="The host address of the mongodb"),mongo_port:int=typer.Option(...,help="The port of the mongodb port")):
    #console = rich.console()
    logger.info(f"{repo_path=},{mongo_host=},{mongo_port=}")
    
    #获取该目录下所有的CVE信息
    cve_dirs,dirs_cnt=find_cve_directories(repo_path=repo_path)

    
if __name__=="__main__":
    typer.run(main)