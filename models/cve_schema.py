# cve_schema.py
from pydantic import BaseModel, Field
from typing import List, Optional

class CVEEntry(BaseModel):
    cve_id: str = Field(description="The CVE ID (e.g., CVE-2024-12345)")
    title: str = Field(description="Short title or summary of the vulnerability")
    description: str = Field(description="Detailed description of the CVE")
    severity: str = Field(description="Severity level (e.g., Critical, High, Medium, Low)")
    cvss_score: Optional[float] = Field(description="CVSS score if available")
    publish_date: str = Field(description="Date when the CVE was published")
    affected_products: List[str] = Field(description="List of affected Intel product lines")
    exploitation_status: Optional[str] = Field(description="Has this been exploited in the wild?")
    patch_available: Optional[bool] = Field(description="True if a patch is available")
    speculative_class: Optional[str] = Field(description="Category like Spectre, Meltdown, MDS, etc.")
    microcode_info: Optional[str] = Field(description="Details on any Intel microcode update or mitigation")

class CVEReport(BaseModel):
    summary: str = Field(description="A short overview of all findings")
    entries: List[CVEEntry] = Field(description="All CVEs analyzed")
    recommendations: List[str] = Field(description="Suggested research or mitigations")
    tags: List[str] = Field(description="Keywords like Spectre, Intel, L1TF, etc.")
