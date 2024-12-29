"""
The prompt to extract sememntic function from the given CVE desc and code snippet."""

# FIXME: 提示大模型减少具体变量的出现
FUNC_EXTRACT_PROMPT_TEMPLATE = """
You are a code analyst tasked with reading and understanding modified functions in a given source code. Your goal is to generate a JSON-formatted string that adhere the FunctionInfoList model with correct field names and detailed content. You must refer the output example to arrange your output.

### Input
- **Vulnerable Source Code**: The full or relevant portion of the source code where the vulnerability exists.
- **Diff**: A diff that highlights the modified functions.

### Output
Generate a JSON-formatted string that adheres to the `FunctionInfoList` model. The output should only include this JSON string without code fences and return nothing else unexpected explain.

#### JSON Model:

class FunctionInfo(BaseModel):
    function_name: str  # Name of the function
    general_purpose: str  # General purpose or description of what the function does
    implementation_details: List[str] = Field(default_factory=list)  # Detailed steps on how the function is implemented before patching

class FunctionInfoList(BaseModel):
    functions: List[FunctionInfo] = Field(default_factory=list)


### Example Output:

[

    {{
            "function_name": "example_function",
            "general_purpose": "This function performs an important security check.",
            "implementation_details": [
                "Step 1: Validates input parameters.",
                "Step 2: Performs a security validation against known vulnerabilities.",
                "Step 3: Returns the result of the validation."
            ]
    }},...
    
]

### Input Data: 
    All files are divided by **filename** line.

#### Vulnerable Source Code

    {vuln_source}
    
#### Patch Source Code

    {patched_source}

#### Diff File

    {diff_source}
     
### Instructions:
1. Carefully read the provided source code and diff.
2. Identify the modified functions based on the diff.
3. For each modified function, determine its general purpose and list the key implementation steps.
4. Format your response as a JSON string which MUST according to the `FunctionInfoList` model.

---
Your response:
"""
