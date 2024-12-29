"""
A seperate tool to validiate if the input string can be parsed to the given pydantic model.
"""
import json
from pydantic import BaseModel, ValidationError
from llm_resp import FunctionInfoList, InitSecInfo


def validate_string_with_model(input_string: str, model: BaseModel):
    """
    Validate if a string can be converted into a given pydantic model.

    Args:
        input_string (str): The JSON string to validate.
        model (BaseModel): The pydantic model to validate against.

    Returns:
        dict: A dictionary containing the validation status and details.
    """
    try:
        # Parse the string to a dictionary
        data = json.loads(input_string)
        # Validate the dictionary with the model
        validated_data = model(**data)
        return {"valid": True, "data": validated_data.dict()}
    except json.JSONDecodeError as e:
        return {"valid": False, "error": f"Invalid JSON: {str(e)}"}
    except ValidationError as e:
        return {"valid": False, "error": e.errors()}


if __name__ == "__main__":
    # Valid JSON string
    valid_json = """
    [
    {
        "function_name": "cdrom_ioctl_media_changed",
        "general_purpose": "Handles the media changed ioctl command for CD-ROM devices, specifically checking if a disc has been changed or selecting a different disc.",
        "implementation_details": [
            "Check if the device supports CDC_SELECT_DISC. If not, call media_changed with an argument to check for media change.",
            "If the argument is CDSL_CURRENT, again call media_changed to check for media change.",
            "Ensure that the argument provided does not exceed the capacity of available discs (prevents out-of-bounds access by casting arg to unsigned int before comparison).",
            "Allocate memory for the information struct and proceed further with media change logic"
        ]
    }
]"""
    print(validate_string_with_model(
        f"{{\"functional_desc\":{valid_json}}}", FunctionInfoList))
