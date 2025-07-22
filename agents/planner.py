# agents/planner.py

from agents import Agent, Runner, trace

planner = Agent(
    name="QueryPlanner",
    instructions=(
        "You are an expert security analyst. Generate search queries to find CVEs "
        "related to speculative execution attacks on Intel CPUs. Include Spectre, Meltdown, MDS, and microcode terms. "
        "Include keywords like CVE, Intel, vulnerability, and relevant years."
    ),
    model="gpt-4o-mini"
)

async def generate_search_queries(topic: str) -> list[str]:
    prompt = f"Generate 5 specific and effective search queries to find CVEs for: {topic}"
    with trace("Generate Search Queries"):
        result = await Runner.run(planner, prompt)
        return result.final_output.strip().splitlines()
