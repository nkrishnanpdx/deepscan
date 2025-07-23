import aiohttp
from datetime import datetime
from typing import List

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

START_DATE = "2017-01-01T00:00:00.000Z"
END_DATE = "2025-12-31T23:59:59.999Z"

async def search_cves(queries: List[str]) -> List[str]:
    results = []

    async with aiohttp.ClientSession() as session:
        for query in queries:
            params = {
                "keywordSearch": query,
                "pubStartDate": START_DATE,
                "pubEndDate": END_DATE,
                "resultsPerPage": 200
            }

            async with session.get(NVD_API_URL, params=params) as resp:
                if resp.status != 200:
                    print(f"[!] Failed to fetch CVEs for query '{query}': Status {resp.status}")
                    continue
                data = await resp.json()

                for item in data.get("vulnerabilities", []):
                    cve = item.get("cve", {})
                    cve_id = cve.get("id", "Unknown-CVE")
                    description = cve.get("descriptions", [{}])[0].get("value", "")

                    if "intel" in description.lower() and any(
                        kw in description.lower()
                        for kw in ["speculative", "transient", "side-channel", "execution", "sampling"]
                    ):
                        results.append(f"{cve_id}: {description.strip()}")

    return results
