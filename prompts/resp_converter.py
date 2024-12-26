"""
This module contains a prompt template designed to instruct a large language model
to convert input JSON data into a format that is directly usable with Pydantic models.
The output should be formatted as an instantiation of the specified Pydantic class.

Example Usage:
1. Insert the JSON input where specified in the prompt template.
2. The generated output should represent the direct instantiation of the Pydantic model
   with values assigned from the provided JSON data.

Note: Ensure that no modifications are made to the keys during conversion.
"""

CONVERTER_PROMPT_TEMPLATE = """
Given the JSON input below, convert it strictly into a Pydantic model format as specified. 
Ensure that the output is directly usable within the context of a Python script with the appropriate Pydantic imports and definitions. Do not modify any keys.

"""
