import os
import time
import urllib.parse
import requests
from groq import Groq
from dotenv import load_dotenv

load_dotenv()
client = Groq(api_key=os.getenv("GROQ_API_KEY"))

def _extract_cvss_score(metrics: dict):
    """
    Tries to extract CVSS baseScore from NVD metrics.
    Priority: v3.1 -> v3.0 -> v2
    Returns: float score or None
    """
    # CVSS v3.1
    try:
        return float(metrics["cvssMetricV31"][0]["cvssData"]["baseScore"])
    except Exception:
        pass

    # CVSS v3.0
    try:
        return float(metrics["cvssMetricV30"][0]["cvssData"]["baseScore"])
    except Exception:
        pass

    # CVSS v2
    try:
        return float(metrics["cvssMetricV2"][0]["cvssData"]["baseScore"])
    except Exception:
        pass

    return None

def search_cves(keyword: str, results_per_page: int = 5):
    """
    Search NVD for real CVEs (free endpoint).
    Returns a LIST of dicts:
      [{"cve_id": "...", "score": 9.8, "description": "...", "url": "..."}, ...]
    """
    encoded = urllib.parse.quote(keyword)
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={encoded}&resultsPerPage={results_per_page}"

    last_error = None

    for attempt in range(3):
        try:
            response = requests.get(url, timeout=10)

            # Basic rate limit handling
            if response.status_code == 429:
                time.sleep(1.5 * (attempt + 1))
                continue

            response.raise_for_status()
            data = response.json()

            cves = []
            for item in data.get("vulnerabilities", []):
                cve = item.get("cve", {})
                cve_id = cve.get("id", "UNKNOWN-CVE")

                # Description
                descriptions = cve.get("descriptions", [])
                description = descriptions[0].get("value", "No description available") if descriptions else "No description available"

                # Score
                metrics = cve.get("metrics", {}) or {}
                score = _extract_cvss_score(metrics)  # float or None

                cves.append({
                    "cve_id": cve_id,
                    "score": score,  # float or None
                    "description": description[:200],
                    "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}"
                })

            if not cves:
                return [{
                    "cve_id": None,
                    "score": None,
                    "description": "No CVEs found for this keyword",
                    "url": None
                }]

            return cves

        except Exception as e:
            last_error = e
            # retry with backoff
            if attempt < 2:
                time.sleep(1.5 * (attempt + 1))
                continue

    # If all retries fail
    return [{
        "cve_id": None,
        "score": None,
        "description": f"CVE lookup failed: {str(last_error)}",
        "url": None
    }]

def cve_agent(log_analysis: str):
    """
    Uses AI to extract up to 3 CVE search keywords from Agent 1 output,
    then queries NVD and returns:
      - keywords (list[str])
      - cve_results_text (str)
      - all_cves_structured (dict[str, list[dict]])
    """

    keyword_prompt = f"""
Based on this log analysis, give me 3 specific software/service keywords
to search for CVEs. Return ONLY the keywords, one per line, nothing else.

Example output:
OpenSSH
Apache
Windows SMB

LOG ANALYSIS:
{log_analysis}
""".strip()

    keyword_response = client.chat.completions.create(
        model=os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile"),
        messages=[
            {"role": "system", "content": "You extract CVE search keywords from security reports."},
            {"role": "user", "content": keyword_prompt}
        ]
    )

    keywords = keyword_response.choices[0].message.content.strip().split("\n")
    keywords = [k.strip() for k in keywords if k.strip()][:3]

    all_cves = {}
    for keyword in keywords:
        print(f"  🔍 Searching CVEs for: {keyword}")
        all_cves[keyword] = search_cves(keyword)

    # Build a human-readable text block for the report
    cve_results = ""
    for keyword, cves in all_cves.items():
        cve_results += f"\n--- {keyword} ---\n"
        for cve in cves:
            cve_id = cve.get("cve_id")
            score = cve.get("score")
            desc = cve.get("description", "")

            score_str = f"{score:.1f}" if isinstance(score, (int, float)) else "N/A"
            if cve_id:
                cve_results += f"  • {cve_id} (Score: {score_str}): {desc}\n"
            else:
                cve_results += f"  • {desc}\n"

    return keywords, cve_results, all_cves