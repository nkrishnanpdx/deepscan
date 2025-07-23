from openai import AsyncOpenAI
import os

client = AsyncOpenAI(api_key=os.getenv("OPENAI_API_KEY"))

ADDITIONAL_KEYWORDS = [
    "Register File Data Sampling (RFDS)",
    "Indirect Target Selection",
    "Branch History Injection",
    "Intra-mode Branch Target Injection",
    "Gather Data Sampling (GDS)",
    "Special Register Buffer Data Sampling (SRBDS)",
    "Microarchitectural Data Sampling (MDS, MSBDS, MFBDS, MLPDS, MDSUM)",
    "L1 Terminal Fault (Foreshadow)",
    "Load Value Injection (LVI)",
    "Retpoline",
    "Snoop-assisted L1 Data Sampling",
    "Sub-page Permission (SPP)",
    "Speculative Store Bypass (Spectre v4)",
    "SWAPGS and Segment Registers",
    "Transactional Synchronization Extensions (Intel TSX)",
    "Bounds Check Bypass (Spectre v1)",
    "Branch Target Injection (Spectre v2)",
    "Rogue Data Cache Load (Spectre v3)",
    "Processor MMIO Stale Data",
    "Trusted Execution Configuration Register Access",
    "Host Firmware Speculative Execution Mitigations"
]

async def generate_search_queries(topic: str) -> list[str]:
    keyword_list = ', '.join(ADDITIONAL_KEYWORDS)
    system_prompt = (
        "You are a security expert generating precise and comprehensive search queries "
        "to find CVEs related to Intel x86 speculative, transient execution, and side-channel vulnerabilities "
        "from 2018 to 2025."
    )
    user_prompt = (
        f"Generate 10 highly precise search queries to find *all* CVEs published between 2017 and 2025 "
        f"related to Intel x86 speculative execution, transient execution, and side-channel vulnerabilities. "
        f"Include keywords like 'speculative execution', 'transient execution', 'side-channel', 'microarchitectural data sampling', "
        f"and specific vulnerability names like Spectre, Meltdown, MDS, Foreshadow, LVI, TAA, GDS, Downfall, SRBDS, RFDS, "
        f"Register File Data Sampling (RFDS), Indirect Target Selection, Branch History Injection, Intra-mode Branch Target Injection, "
        f"Gather Data Sampling (GDS), Special Register Buffer Data Sampling (SRBDS), Microarchitectural Data Sampling (MDS, MSBDS, MFBDS, MLPDS, MDSUM), "
        f"L1 Terminal Fault (Foreshadow), Load Value Injection (LVI), Retpoline, Snoop-assisted L1 Data Sampling, Sub-page Permission (SPP), "
        f"Speculative Store Bypass (Spectre v4), SWAPGS and Segment Registers, Transactional Synchronization Extensions (Intel TSX), "
        f"Bounds Check Bypass (Spectre v1), Branch Target Injection (Spectre v2), Rogue Data Cache Load (Spectre v3), Processor MMIO Stale Data, "
        f"Trusted Execution Configuration Register Access, Host Firmware Speculative Execution Mitigations. "
        f"Add explicit date filters like 'published between 2017 and 2025' where possible."
    )

    response = await client.chat.completions.create(
        model="gpt-4o",
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ],
        max_tokens=250,
        temperature=0.3,
    )

    content = response.choices[0].message.content
    return [line.strip("-*1234567890. ").strip() for line in content.strip().splitlines() if line.strip()]
