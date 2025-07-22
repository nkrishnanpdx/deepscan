from dotenv import load_dotenv
import asyncio
from agents.planner import generate_search_queries
from agents.search import search_cves
from agents.summarizer import summarize_cves
from agents.reporter import generate_report

load_dotenv(override=True)

async def main():
    topic = "Speculative execution CVEs on Intel CPUs from Jan 2024 to now"
    
    # Step 1: Generate search queries
    queries = await generate_search_queries(topic)
    print("Generated queries:", queries)

    # Step 2: Search CVEs and gather raw data
    raw_cves = await search_cves(queries)
    print(f"Found {len(raw_cves)} CVEs")

    # Step 3: Summarize CVEs
    summaries = await summarize_cves(raw_cves)
    print("Summarized CVEs")

    # Step 4: Generate final report
    report = await generate_report(summaries)
    with open("deepsecscan_report.md", "w") as f:
        f.write(report)
    print("Report written to deepsecscan_report.md")

if __name__ == "__main__":
    asyncio.run(main())
