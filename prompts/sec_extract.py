"""
To save the prompts used to extract security sementics in two stages: init and abstract
"""

# FIXME: 需要额外让大模型注意增加叙述的通用性

INIT_SEC_EXTRACTION = """

You are a security analyst tasked with analyzing a CVE and understanding the details of the vulnerability and its patch. Your goal is to generate a JSON-formatted string that adhere the InitSecInfo model with detailed content.

# Input
- **CVE Metadata**: The metadata associated with the CVE, including the CVE number, title, description, weaknesses, and patch metadata.
- **Patch Metadata**: Details about the patch commit, including SHA, message, repository, vulnerable code, patched code, and diff.

# Output
Generate a JSON-formatted string that strictly adheres to the `InitSecInfo` model. The output should only include this JSON string and nothing else .

# JSON Model
```Python


class InitSecInfo(BaseModel):
    cve_id: str  # CVE 编号
    description: str  # 漏洞的详细描述
    vulnerability_cause_details: str = ""  # 漏洞存在的详细解释
    patch_details: str = ""  # 补丁中所做的更改以修复漏洞的摘要


```

# Example Output


{
    "cve_id": "CVE-2021-12345",
    "description": "A use-after-free vulnerability in the handling of network packets.",
    "vulnerability_cause_details": "The vulnerability occurs because the application fails to properly free memory before reusing it, leading to a situation where freed memory is accessed after it has been released.",
    "patch_details": "The patch introduces a mechanism to ensure that memory is not reused until it is safely freed. Specifically, the patch modifies the function 'free_and_reuse' by adding a check to confirm that the memory block is no longer in use before freeing it."
}


# Input Data

## CVE Number
{cve_number}

## Title
{title}

## Description
{description}

## Weaknesses
{weaknesses}

## Patch Commit Message
{commit_message}

## Repository
{repo}

## Vulnerable Code
{vuln_source}

## Patched Code

{patched_source}

## Diff Code
{diff_source}

# Instructions
1. Carefully read the provided CVE metadata and patch metadata.
2. Analyze the vulnerability based on the CVE description and weaknesses.
3. Determine the detailed reasons why the vulnerability exists.
4. Summarize the key changes made in the patch to fix the vulnerability.
5. Format your response as a JSON string according to the `InitSecInfo` model without any other output.

---
Your response:
"""
