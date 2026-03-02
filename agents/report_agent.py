import os
import json
from groq import Groq
from dotenv import load_dotenv
from datetime import datetime
from pathlib import Path

load_dotenv()
client = Groq(api_key=os.getenv("GROQ_API_KEY"))

def compute_risk(cve_structured):
    """
    Uses CVSS scores from structured CVE results to compute:
    - numeric risk score
    - risk label (Critical/High/Medium/Low)
    - counts by severity band
    """
    if not cve_structured:
        return {
            "risk_label": "Unknown",
            "risk_score": 0,
            "counts": {"critical": 0, "high": 0, "medium": 0, "low": 0}
        }

    critical = high = medium = low = 0

    def to_float(x):
        try:
            return float(x)
        except Exception:
            return None

    for _, cves in cve_structured.items():
        for item in cves:
            s = to_float(item.get("score"))
            if s is None:
                continue
            if s >= 9.0:
                critical += 1
            elif s >= 7.0:
                high += 1
            elif s >= 4.0:
                medium += 1
            else:
                low += 1

    risk_score = critical * 5 + high * 3 + medium * 1 + low * 0.5

    if risk_score >= 16:
        label = "Critical"
    elif risk_score >= 9:
        label = "High"
    elif risk_score >= 4:
        label = "Medium"
    else:
        label = "Low"

    return {
        "risk_label": label,
        "risk_score": risk_score,
        "counts": {"critical": critical, "high": high, "medium": medium, "low": low}
    }

def report_agent(log_analysis, cve_results, mitre_mapping, keywords, cve_structured=None):
    risk_calc = compute_risk(cve_structured)

    prompt = f"""
You are a senior cybersecurity analyst writing an executive incident report.
Combine all findings below into a clean, professional security report with these sections:

1. EXECUTIVE SUMMARY (2-3 sentences, non-technical)
2. INCIDENT OVERVIEW
3. ATTACK TIMELINE
4. CVE VULNERABILITIES IDENTIFIED
5. MITRE ATT&CK MAPPING
6. RISK SEVERITY (Critical / High / Medium / Low + justification)
7. IMMEDIATE ACTIONS REQUIRED
8. LONG-TERM RECOMMENDATIONS

IMPORTANT:
- Use this computed CVSS-based risk as the baseline for section 6:
{risk_calc}

LOG ANALYSIS:
{log_analysis}

CVE FINDINGS:
{cve_results}

MITRE MAPPING:
{mitre_mapping}
""".strip()

    # Generate report text (LLM). If it fails, fall back to a basic report.
    try:
        response = client.chat.completions.create(
            model=os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile"),
            messages=[
                {"role": "system", "content": "You are a senior cybersecurity analyst writing professional incident reports."},
                {"role": "user", "content": prompt}
            ]
        )
        report = response.choices[0].message.content
    except Exception as e:
        report = (
            "EXECUTIVE SUMMARY:\n"
            f"Automated analysis failed to generate a full narrative report due to an LLM error: {str(e)}\n\n"
            "INCIDENT OVERVIEW:\n"
            "See log analysis, CVE findings, and MITRE mapping below.\n\n"
            "LOG ANALYSIS:\n"
            f"{log_analysis}\n\n"
            "CVE FINDINGS:\n"
            f"{cve_results}\n\n"
            "MITRE ATT&CK MAPPING:\n"
            f"{mitre_mapping}\n\n"
            "RISK SEVERITY:\n"
            f"{risk_calc['risk_label']} (score={risk_calc['risk_score']})\n"
        )

    # Save outputs with timestamp (save next to main.py)
    out_dir = Path(".")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    txt_filename = out_dir / f"security_report_{timestamp}.txt"
    json_filename = out_dir / f"security_report_{timestamp}.json"

    # TXT report
    with open(txt_filename, "w", encoding="utf-8") as f:
        f.write("SECURITY INCIDENT REPORT\n")
        f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Keywords Analyzed: {', '.join(keywords)}\n")
        f.write(f"Computed Risk: {risk_calc['risk_label']} (score={risk_calc['risk_score']})\n")
        f.write("=" * 60 + "\n\n")
        f.write(report)

    # JSON artifact (portfolio-level)
    payload = {
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "keywords": keywords,
        "risk": risk_calc,
        "log_analysis": log_analysis,
        "cve_results_text": cve_results,
        "cve_structured": cve_structured,
        "mitre_mapping": mitre_mapping,
        "final_report_text": report
    }

    with open(json_filename, "w", encoding="utf-8") as jf:
        json.dump(payload, jf, indent=2)

    # Return strings for main.py printing
    return report, str(txt_filename), str(json_filename), risk_calc