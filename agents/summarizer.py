import re
from typing import List, Dict
from openai import AsyncOpenAI
import os
from openai.types.chat import ChatCompletionSystemMessageParam, ChatCompletionUserMessageParam

client = AsyncOpenAI(api_key=os.getenv("OPENAI_API_KEY"))

async def summarize_cves(cve_list: List[str]) -> Dict[str, str]:
    summaries = {}
    batch_size = 5

    for i in range(0, len(cve_list), batch_size):
        batch = cve_list[i:i+batch_size]

        system_message: ChatCompletionSystemMessageParam = {
            "role": "system",
            "content": (
                "You are a cybersecurity analyst. Summarize each CVE briefly in this format:\n"
                "**<CVE-ID>**: <Short description>\n"
                "Keep descriptions concise and clear."
            ),
        }
        user_message: ChatCompletionUserMessageParam = {
            "role": "user",
            "content": "\n".join(batch)
        }

        # Note use of 'acreate' here
        response = await client.chat.completions.create(
            model="gpt-4o",
            messages=[system_message, user_message],
            temperature=0.3,
            max_tokens=1000,
        )

        output = response.choices[0].message.content

        if output:
            for line in output.splitlines():
                match = re.match(r"\*\*(CVE-\d{4}-\d{4,7})\*\*:?\s*(.+)", line)
                if match:
                    cve_id = match.group(1)
                    description = match.group(2).strip()
                    summaries[cve_id] = description

    return summaries
