# agents/reporter.py
from models.cve_schema import CVEReport, CVEEntry
from typing import List

def format_cve_entry(entry: CVEEntry) -> str:
    patch_status = "Yes" if entry.patch_available else "No"
    microcode = entry.microcode_info or "N/A"
    exploitation = entry.exploitation_status or "Unknown"

    return (
        f"### {entry.cve_id}: {entry.title}\n"
        f"- **Published:** {entry.publish_date}\n"
        f"- **Severity:** {entry.severity} (CVSS: {entry.cvss_score if entry.cvss_score else 'N/A'})\n"
        f"- **Affected Products:** {', '.join(entry.affected_products)}\n"
        f"- **Speculative Class:** {entry.speculative_class or 'Unknown'}\n"
        f"- **Exploitation Status:** {exploitation}\n"
        f"- **Patch Available:** {patch_status}\n"
        f"- **Microcode Info:** {microcode}\n"
        f"- **Description:** {entry.description}\n"
    )

def generate_report(cve_entries: List[CVEEntry], summary: str, recommendations: List[str], tags: List[str]) -> str:
    report_lines = [
        "# Speculative Execution CVE Report on Intel CPUs\n",
        f"## Summary\n{summary}\n",
        f"## Tags\n{', '.join(tags)}\n",
        "## CVE Details\n"
    ]

    for entry in cve_entries:
        report_lines.append(format_cve_entry(entry))
        report_lines.append("\n---\n")

    report_lines.append("## Recommendations\n")
    for rec in recommendations:
        report_lines.append(f"- {rec}")

    return "\n".join(report_lines)
