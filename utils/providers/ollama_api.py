import requests
import json


class OllamaChatBase:
    """A class for interacting with the chat completion API."""

    def __init__(self, base_url: str, model: str):
        """
        Initializes the ChatAPI class.

        Args:
            base_url (str): The base URL of the API (e.g., "http://localhost:8000").
            model (str): The model to be used for chat completions 
                         (e.g., "Qwen/Qwen2.5-Coder-32B-Instruct").
        """
        self.base_url = base_url
        self.model = model

    def send_message(self, user_message: str) -> dict:
        """
        Sends a chat message to the API and returns the response.

        Args:
            user_message (str): The message content from the user.

        Returns:
            str: The API's response's message content.
        """
        url = f"{self.base_url}/v1/chat/completions"
        headers = {"Content-Type": "application/json"}
        payload = {
            "model": self.model,
            "messages": [
                {
                    "role": "user",
                    "content": user_message
                }
            ]
        }

        try:
            response = requests.post(
                url, headers=headers, data=json.dumps(payload))
            response.raise_for_status()  # Raise an HTTPError for bad responses
            # Return the raw message content
            return response.json()["choices"][0]["message"]["content"]
        except requests.exceptions.RequestException as e:
            return {"error": str(e)}
