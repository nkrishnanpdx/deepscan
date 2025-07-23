import os
import re
import aiohttp
from bs4 import BeautifulSoup
from typing import List
from openai import AsyncOpenAI
from dotenv import load_dotenv

load_dotenv()

client = AsyncOpenAI(api_key=os.getenv("OPENAI_API_KEY"))

SEARCH_ENGINE = "https://www.google.com/search"
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
}

TARGET_DOMAINS = ["cve.mitre.org", "intel.com", "security.archlinux.org", "cvedetails.com"]
MAX_GOOGLE_PAGES = 3

async def scrape_cvedetails_intel(session, max_pages=3):
    base_url = "https://www.cvedetails.com/vulnerability-list/vendor_id-26/product_id-0/Intel.html"
    cves = []
    for page_num in range(1, max_pages + 1):
        url = f"{base_url}?page={page_num}"
        async with session.get(url) as resp:
            if resp.status != 200:
                print(f"[!] Failed to fetch CVE Details page {page_num}: {resp.status}")
                continue
            html = await resp.text()
            soup = BeautifulSoup(html, "html.parser")
            for a in soup.select("table.searchresults a[href^='/cve/CVE-']"):
                cve_id = a.text.strip()
                if cve_id.startswith("CVE-") and cve_id not in cves:
                    cves.append(cve_id)
    return cves

async def search_cves(queries: List[str]) -> List[str]:
    found_cves = []
    async with aiohttp.ClientSession(headers=HEADERS) as session:
        for query in queries:
            print(f"🔍 Searching Google for: {query}")
            for page_num in range(MAX_GOOGLE_PAGES):
                start = page_num * 10
                params = {
                    "q": f"site:{' OR site:'.join(TARGET_DOMAINS)} {query}",
                    "start": str(start)
                }
                async with session.get(SEARCH_ENGINE, params=params, ssl=False) as resp:
                    if resp.status != 200:
                        print(f"[!] Failed: {resp.status}")
                        continue

                    html = await resp.text()
                    soup = BeautifulSoup(html, "html.parser")
                    page_text = soup.get_text()

                    system_msg = {"role": "system", "content": "You are a cybersecurity analyst extracting CVE identifiers from search results."}
                    user_msg = {
                        "role": "user",
                        "content": f"Here is a Google search result page for the query: {query}\n\n{text_limiter(page_text)}\n\nList all CVE identifiers mentioned, only one per line."
                    }

                    try:
                        response = await client.chat.completions.create(
                            model="gpt-4o",
                            messages=[system_msg, user_msg],
                            temperature=0.2,
                            max_tokens=800,
                        )
                        gpt_output = response.choices[0].message.content
                        matches = re.findall(r"CVE-\d{4}-\d{4,7}", gpt_output)
                        for cve in matches:
                            if cve not in found_cves:
                                found_cves.append(cve)
                    except Exception as e:
                        print(f"[!] OpenAI error: {e}")

        print("🔍 Scraping CVEDetails Intel vendor pages...")
        cvedetails_cves = await scrape_cvedetails_intel(session)
        for cve in cvedetails_cves:
            if cve not in found_cves:
                found_cves.append(cve)

    return found_cves

def text_limiter(text: str, max_chars: int = 4000) -> str:
    return text[:max_chars]
