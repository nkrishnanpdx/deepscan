# agents/search.py

from agents import Agent, Runner, trace
from typing import List

search_agent = Agent(
    name="SearchAgent",
    instructions="Search for recent speculative execution CVEs on Intel products. Return each result with CVE ID, title, date, and link.",
    model="gpt-4o-mini"
)

async def search_cves(queries: List[str]) -> List[str]:
    results = []
    for query in queries:
        with trace(f"Search: {query}"):
            result = await Runner.run(search_agent, f"Search and list speculative execution CVEs for: {query}. Give only CVE ID, title, date.")
            results.append(result.final_output.strip())
    return results
