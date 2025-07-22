# agents/summarizer.py

from agents import Agent, Runner, trace
from typing import List
from schemas.cve_schema import CVEEntry  # We'll define this next

summarizer = Agent(
    name="CVEExtractor",
    instructions=(
        "You are a vulnerability analyst. Parse each CVE entry and extract:\n"
        "- CVE ID\n- Title\n- Affected CPUs or microarchitectures\n"
        "- Description (1–2 lines)\n- Speculative Class (Spectre, Meltdown, MDS, etc)\n"
        "- CVSS score (if known)\n- Fix/Patch Info (if any)"
    ),
    model="gpt-4o-mini"
)

async def summarize_cves(raw_entries: List[str]) -> List[CVEEntry]:
    summaries = []

    for entry in raw_entries:
        with trace("Summarize CVE"):
            result = await Runner.run(summarizer, f"Summarize this entry:\n{entry}")
            data = parse_summary(result.final_output)
            if data:
                summaries.append(data)

    return summaries

def parse_summary(text: str) -> CVEEntry | None:
    try:
        lines = text.strip().splitlines()
        return CVEEntry(
            cve_id=lines[0].split(":")[-1].strip(),
            title=lines[1].split(":")[-1].strip(),
            affected=lines[2].split(":")[-1].strip(),
            description=lines[3].split(":")[-1].strip(),
            class_type=lines[4].split(":")[-1].strip(),
            cvss=lines[5].split(":")[-1].strip(),
            fix_info=lines[6].split(":")[-1].strip()
        )
    except Exception as e:
        print("Failed to parse:", text)
        return None
