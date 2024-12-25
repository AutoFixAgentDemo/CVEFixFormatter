"""
To define the standard model of LLM with response variable.
"""

import json
from typing import List
from pydantic import BaseModel, Field

from typing import List
from pydantic import BaseModel, Field


class FunctionInfo(BaseModel):
    function_name: str = Field(
        default="", description="The name of the function")
    file_name: str = Field(
        default="", description="The path to the file where the function is defined")
    general_purpose: str = Field(
        default="", description="A brief description of the function's purpose")
    implementation_details: List[str] = Field(
        default_factory=list,
        description="Detailed information about the function's implementation"
    )


class FunctionInfoList(BaseModel):
    functions: List[FunctionInfo] = Field(
        default_factory=list,
        description="A list of FunctionInfo objects representing various functions"
    )


class InitSecInfo(BaseModel):
    cve_id: str = Field(default="", description="CVE number")  # CVE 编号
    description: str = Field(
        default="",
        description="The detailed description of the CVE"
    )  # 漏洞的详细描述
    vulnerability_cause_details: str = Field(
        default="",
        description="Detailed explanation of why the vulnerability exists"
    )  # 漏洞存在的详细解释
    patch_details: str = Field(
        default="",
        description="Summary of changes made in the patch to fix the vulnerability"
    )


@DeprecationWarning
class AbstractSecInfo(BaseModel):
    cve_id: str = Field(default="", description="CVE number")  # CVE 编号
    abstract_cause: str = Field(
        default="", description="A brief summary of the cause of the vulnerability")  # 漏洞的简要描述
    solution_desc: str = Field(
        default="", description="Description of the solution to address the vulnerability")  # 漏洞的解决方案描述
