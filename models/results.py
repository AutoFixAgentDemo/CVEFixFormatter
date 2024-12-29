from enum import Enum
from pydantic import BaseModel
from typing import Optional, Literal, List, Dict, Union


class StatusEnum(str, Enum):
    SUCCESS = "success"
    NO_VALID_COMMIT = "no_valid_commit"
    ALREADY_PARSED = "already_parsed"
    MULTIPLE_COMMITS = "multiple_commits"
    LLM_PARSE_FAILED = "llm_parse_failed"


class ExecutionResult(BaseModel):
    status: StatusEnum
    cve_number: str = "N/A"  # 适用于 "already_parsed" 状态
    message: str = "No additional message"  # 额外的描述信息或详细日志


class ExecutionSummary:
    def __init__(self):
        self.result_counts: Dict[str, int] = {
            "success": 0,
            "no_valid_commit": 0,
            "already_parsed": 0,
            "multiple_commits": 0,
            "llm_parse_failed": 0,
        }
        self.problematic_cves: Dict[str, List[str]] = {
            "no_valid_commit": [],
            "already_parsed": [],
            "multiple_commits": [],
            "llm_parse_failed": [],
        }

    def update(self, result: Dict[str, Union[str, None]]):
        status = result.get("status")
        cve_number = result.get("cve_number")
        if status in self.result_counts:
            self.result_counts[status] += 1
            if status in self.problematic_cves and cve_number:
                self.problematic_cves[status].append(cve_number)

    def display_summary(self):
        # Return the summary in a formatted string
        summary_str = ""
        for status, count in self.result_counts.items():
            summary_str += f"{status}: {count}\n"
            if self.problematic_cves[status]:
                summary_str += f"  {self.problematic_cves[status]}\n"
        return summary_str
