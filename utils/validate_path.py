import os
import typer
import glob


def validate_path(repo_path: str) -> str:
    """Validate that the repo_path is an existing directory."""
    if not os.path.exists(repo_path):
        raise typer.BadParameter(f"The provided path '{
                                 repo_path}' does not exist.")
    if not os.path.isdir(repo_path):
        raise typer.BadParameter(f"The provided path '{
                                 repo_path}' is not a directory.")
    return repo_path


def list_all_dirs_in_path(path: str) -> list:
    """List all directories in the given path."""
    return [d for d in os.listdir(path) if os.path.isdir(os.path.join(path, d))]


def get_unique_json_file_path(directory):
    # 查找目录下所有的 JSON 文件
    json_files = glob.glob(os.path.join(directory, "*.json"))

    # 确保只有一个 JSON 文件
    if len(json_files) == 1:
        return json_files[0]  # 返回唯一 JSON 文件的路径
    elif len(json_files) == 0:
        raise FileNotFoundError(
            f"No JSON file found in the specified directory {directory}.")
    else:
        raise ValueError(
            f"Multiple JSON files found in the specified directory. {directory}")


if __name__ == "__main__":

    print(get_unique_json_file_path(
        "/home/louisliu/Codes/VulnCodeCollector/data/boundary/CVE-2018-10940"))
