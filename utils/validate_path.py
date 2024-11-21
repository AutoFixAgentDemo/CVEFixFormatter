import os
import typer
def validate_path(repo_path: str) -> str:
    """Validate that the repo_path is an existing directory."""
    if not os.path.exists(repo_path):
        raise typer.BadParameter(f"The provided path '{repo_path}' does not exist.")
    if not os.path.isdir(repo_path):
        raise typer.BadParameter(f"The provided path '{repo_path}' is not a directory.")
    return repo_path