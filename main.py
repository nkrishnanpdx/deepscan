from dotenv import load_dotenv
import asyncio
import re
from agents.planner import generate_search_queries
from agents.search import search_cves
from agents.summarizer import summarize_cves
from agents.reporter import generate_report
from models.cve_schema import CVEReport, CVEEntry

load_dotenv(override=True)

async def main():
    try:
        topic = (
            "Speculative execution, transient execution, side-channel vulnerabilities "
            "on Intel x86 CPUs from 2018 to 2025 including Spectre, Meltdown, MDS, microcode updates."
        )
        
        # Step 1: Generate search queries
        queries = await generate_search_queries(topic)
        print("✅ Generated queries:", queries)

        # Step 2: Search CVEs and gather raw data (likely list of strings)
        raw_cves = await search_cves(queries)
        print("Sample raw CVE data:", raw_cves[0] if raw_cves else "No data")
        print(f"✅ Found {len(raw_cves)} raw CVE entries")

        if not raw_cves:
            print("No CVEs found, exiting early.")
            return

        # Step 3: Parse raw text lines into structured CVE dicts
        cve_entries_parsed = []
        for line in raw_cves:
            matches = re.findall(r'(CVE-\d{4}-\d{4,7})', line)
            for cve_id in matches:
                cve_entries_parsed.append({
                    "cve_id": cve_id,
                    "description": line.strip()
                })

        if not cve_entries_parsed:
            print("No structured CVE entries parsed, exiting.")
            return

        print(f"✅ Parsed {len(cve_entries_parsed)} structured CVE entries")

        # Step 4: Summarize CVEs into dict cve_id -> description (this uses batching internally now)
        summary_dict = await summarize_cves([entry['cve_id'] for entry in cve_entries_parsed])
        print(f"✅ Summarized {len(summary_dict)} CVEs")

        # Step 5: Build CVEEntry objects using summaries where available
        cve_entries = []
        for raw_cve in cve_entries_parsed:
            cve_id = raw_cve.get('cve_id')
            description = summary_dict.get(cve_id, raw_cve.get('description', 'No description available'))

            entry = CVEEntry(
                cve_id=cve_id,
                title=cve_id,
                severity='Unknown',
                publish_date='Unknown',
                affected_products=[],
                description=description if description is not None else "No description available",
                exploitation_status=None,
                patch_available=None,
                speculative_class=None,
                microcode_info=None
            )
            cve_entries.append(entry)

        print(f"✅ Created {len(cve_entries)} CVEEntry objects")

        # Step 6: Prepare CVEReport with entries
        report_data = CVEReport(
            summary="This report covers speculative, transient, and side-channel execution vulnerabilities on Intel x86 CPUs from 2018 to present.",
            entries=cve_entries,
            recommendations=[
                "Apply all microcode and firmware updates promptly.",
                "Monitor security advisories for new speculative execution vulnerabilities.",
                "Implement mitigations against side-channel attacks in software and hardware."
            ],
            tags=["Spectre", "Meltdown", "MDS", "Speculative Execution", "Transient Execution", "Side-Channel", "Intel x86"]
        )

        print("✅ Prepared CVEReport data")

        # Step 7: Generate and save markdown report
        generate_report(
            cve_entries=report_data.entries,
            summary=report_data.summary,
            recommendations=report_data.recommendations,
            tags=report_data.tags,
            output_file="deepsecscan_report.md"
        )
        print("✅ Report generated and saved as deepsecscan_report.md")

    except Exception as e:
        print("❌ Error during execution:", e)

if __name__ == "__main__":
    asyncio.run(main())
