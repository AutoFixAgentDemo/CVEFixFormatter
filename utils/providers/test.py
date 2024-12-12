"""
To test the avalibality of the provider
"""

import requests
import yaml
from ollama_api import OllamaChatBase


if __name__ == "__main__":
    with open("./config.yaml", "r") as f:
        config = yaml.safe_load(f)
        base_url = config["llm"]["base_url"]
        model = config["llm"]["model"]
    base = OllamaChatBase(base_url, model)
    print(base.send_message("Introduce to me about yourself!"))
