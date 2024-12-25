"""
The basic model of CVEs' metadata 
"""


from pydantic import BaseModel, Field
from typing import List
from bson.objectid import ObjectId


class PatchMeta(BaseModel):
    commit_sha: str = Field(default="", description="The commit sha")
    commit_message: str = Field(default="", description="The commit message")
    repo: str = Field(
        default="", description="The repo the commit belongs to, e.g. torvalds/linux")
    vulnerable_codes_id: List[str] = Field(
        default_factory=list, description="The ids of vulnerable files in GridFS")
    patched_code_id: List[str] = Field(
        default_factory=list, description="The ids of patched files in GridFS")
    diff_id: List[str] = Field(
        default_factory=list, description="The ids of diff files in GridFS")


class CVEMeta(BaseModel):
    cve_number: str = ""
    title: str = ""
    description: str = ""
    weaknesses: List[str] = Field(default_factory=list)
    patch_meta: PatchMeta = Field(default_factory=PatchMeta)
