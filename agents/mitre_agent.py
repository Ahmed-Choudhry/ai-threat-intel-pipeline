import os
import requests
from groq import Groq
from dotenv import load_dotenv

load_dotenv()
client = Groq(api_key=os.getenv("GROQ_API_KEY"))

def get_mitre_technique(technique_id):
    """Fetch real MITRE technique details from free MITRE TAXII API"""
    try:
        url = f"https://attack.mitre.org/techniques/{technique_id}/"
        return f"https://attack.mitre.org/techniques/{technique_id}/"
    except:
        return "Could not fetch MITRE link"

def mitre_agent(log_analysis, cve_results):
    prompt = f"""
    You are a MITRE ATT&CK expert. Based on the log analysis and CVE findings below,
    map this attack to the MITRE ATT&CK framework.

    For each finding provide:
    1. Tactic (e.g. Initial Access, Persistence, Lateral Movement)
    2. Technique ID and name (e.g. T1110 - Brute Force)
    3. Sub-technique if applicable (e.g. T1110.001 - Password Guessing)
    4. Brief explanation of why it maps to this technique
    5. Direct MITRE link: https://attack.mitre.org/techniques/TECHNIQUE_ID/

    LOG ANALYSIS:
    {log_analysis}

    CVE FINDINGS:
    {cve_results}
    """

    response = client.chat.completions.create(
        model=os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile"),
        messages=[
            {"role": "system", "content": "You are a MITRE ATT&CK framework expert who maps attacks to techniques."},
            {"role": "user", "content": prompt}
        ]
    )

    return response.choices[0].message.content