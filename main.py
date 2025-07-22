from dotenv import load_dotenv
import asyncio
from agents.planner import generate_search_queries
from agents.search import search_cves
from agents.summarizer import summarize_cves
from agents.reporter import generate_report
from models.cve_schema import CVEReport

load_dotenv(override=True)

async def main():
    topic = "Speculative execution CVEs on Intel CPUs from Jan 2024 to now"
    
    # Step 1: Generate search queries
    queries = await generate_search_queries(topic)
    print("Generated queries:", queries)

    # Step 2: Search CVEs and gather raw data
    raw_cves = await search_cves(queries)
    print(f"Found {len(raw_cves)} CVEs")

    # Step 3: Summarize CVEs into CVEEntry list
    summaries = await summarize_cves(raw_cves)
    print("Summarized CVEs")

    # Step 4: Prepare report data
    report_data = CVEReport(
        summary="This report summarizes speculative execution vulnerabilities on Intel CPUs from Jan 2024 to present...",
        entries=summaries,
        recommendations=[
            "Apply all available microcode updates immediately.",
            "Focus on detection of speculative side-channel attack patterns.",
            "Research next-gen hardware mitigations for Spectre variants."
        ],
        tags=["Spectre", "MDS", "Intel", "Speculative Execution", "Microcode"]
    )

    # Step 5: Generate final report markdown
    report_md = generate_report(
        cve_entries=report_data.entries,
        summary=report_data.summary,
        recommendations=report_data.recommendations,
        tags=report_data.tags
    )

    # Step 6: Write report to file
    with open("deepsecscan_report.md", "w") as f:
        f.write(report_md)
    print("Report written to deepsecscan_report.md")

if __name__ == "__main__":
    asyncio.run(main())
