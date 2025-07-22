from typing import List, Optional
from models.cve_schema import CVEEntry

def generate_report(
    cve_entries: List[CVEEntry], 
    summary: str, 
    recommendations: List[str], 
    tags: List[str],
    output_file: Optional[str] = None
) -> str:
    md = "# 🔍 DeepSecScan Report: Speculative and Transient Execution CVEs (Intel x86, 2018–2025)\n\n"
    
    md += "## 📝 Executive Summary\n\n"
    md += f"{summary}\n\n"

    md += "## 🛠️ CVE Details\n\n"
    for cve in cve_entries:
        md += f"### {cve.cve_id} — {cve.title}\n"
        md += f"- **Severity:** {cve.severity or 'N/A'}\n"
        md += f"- **CVSS Score:** {cve.cvss_score if cve.cvss_score is not None else 'N/A'}\n"
        md += f"- **Published Date:** {cve.publish_date}\n"
        md += f"- **Affected Products:** {', '.join(cve.affected_products) if cve.affected_products else 'N/A'}\n"
        if cve.exploitation_status:
            md += f"- **Exploitation Status:** {cve.exploitation_status}\n"
        if cve.patch_available is not None:
            md += f"- **Patch Available:** {'Yes' if cve.patch_available else 'No'}\n"
        if cve.speculative_class:
            md += f"- **Vulnerability Class:** {cve.speculative_class}\n"
        if cve.microcode_info:
            md += f"- **Microcode Info:** {cve.microcode_info}\n"
        
        md += f"\n**Description:**\n{cve.description.strip()}\n\n---\n\n"

    if recommendations:
        md += "## ✅ Mitigation Recommendations\n\n"
        for rec in recommendations:
            md += f"- {rec.strip()}\n"
        md += "\n"

    if tags:
        md += "## 🏷️ Tags\n\n"
        md += ", ".join(tags) + "\n"

    # Optional write to file
    if output_file:
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(md)
        print(f"[✓] Markdown report written to: {output_file}")

    return md
