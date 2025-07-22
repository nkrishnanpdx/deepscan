from openai import AsyncOpenAI
import os

client = AsyncOpenAI(api_key=os.getenv("OPENAI_API_KEY"))

async def search_cves(queries: list[str]) -> list[str]:
    prompt = (
        "You are a cybersecurity analyst helping to identify CVEs related to Intel x86 speculative execution, side-channel, and transient execution attacks from 2018 to 2025.\n\n"
        "From the following search queries, extract relevant CVE entries:\n\n"
        + "\n".join(queries)
    )

    response = await client.chat.completions.create(
        model="gpt-4o",
        messages=[
            {"role": "system", "content": "You are an expert at identifying relevant CVEs from query logs."},
            {"role": "user", "content": prompt},
        ],
        max_tokens=1000,
        temperature=0.2,
    )

    raw_text = response.choices[0].message.content
    if raw_text:
        return [line.strip("-*• \n") for line in raw_text.splitlines() if "CVE" in line]
    else:
        return []
