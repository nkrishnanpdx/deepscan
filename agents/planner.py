from openai import AsyncOpenAI
import os

client = AsyncOpenAI(api_key=os.getenv("OPENAI_API_KEY"))

async def generate_search_queries(topic: str) -> list[str]:
    response = await client.chat.completions.create(
        model="gpt-4o",
        messages=[
            {
                "role": "system",
                "content": (
                    "You are a security expert generating precise and comprehensive search queries "
                    "to find CVEs related to Intel x86 speculative, transient execution, and side-channel vulnerabilities "
                    "from 2018 to 2025."
                )
            },
            {
                "role": "user",
                "content": (
                    f"Generate 5 specific, effective search queries for CVEs related to: {topic}. "
                    "Include relevant terms such as Spectre, Meltdown, Foreshadow, MDS, GDS, Downfall, Data Sampling, "
                    "Register File Data Sampling, Branch Target Injection, Branch Privilege Injection, Branch History Attacks, "
                    "BPU attacks, Crosstalk, Special Register Buffer Data Sampling, microcode updates, patches, and any other related microarchitectural vulnerabilities."
                )
            }
        ],
        max_tokens=250,
        temperature=0.3,
    )
    content = response.choices[0].message.content
    text = content.strip() if content else ""
    return [line.strip("-*1234567890. ").strip() for line in text.splitlines() if line.strip()]
