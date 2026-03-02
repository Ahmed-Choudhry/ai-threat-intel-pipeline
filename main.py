from agents.log_agent import analyze_logs
from agents.cve_agent import cve_agent
from agents.mitre_agent import mitre_agent
from agents.report_agent import report_agent

import sys
from pathlib import Path

def main():
    # Choose log file (default: sample_logs.txt)
    log_path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("sample_logs.txt")

    if not log_path.exists():
        raise FileNotFoundError(f"Log file not found: {log_path.resolve()}")

    logs = log_path.read_text(encoding="utf-8", errors="ignore")

    print("\n" + "="*50)
    print("🤖 MULTI-AGENT SECURITY ANALYSIS STARTING")
    print("="*50)
    print(f"📄 Log source: {log_path.name}")

    # Agent 1
    print("\n[Agent 1] 📋 Analyzing logs...")
    log_analysis = analyze_logs(logs)
    print("✅ Log analysis complete")

    # Agent 2
    print("\n[Agent 2] 🔍 Searching CVE database...")
    keywords, cve_results, cve_structured = cve_agent(log_analysis)
    print("✅ CVE lookup complete")

    # Agent 3
    print("\n[Agent 3] 🗺️  Mapping to MITRE ATT&CK...")
    mitre_mapping = mitre_agent(log_analysis, cve_results)
    print("✅ MITRE mapping complete")

    # Agent 4
    print("\n[Agent 4] 📝 Generating final report...")
    final_report, filename, json_filename, risk_calc = report_agent(log_analysis, cve_results, mitre_mapping, keywords, cve_structured=cve_structured)
    print(f"✅ Report saved to: {filename}")
    print(f"✅ JSON saved to: {json_filename}")
    print(f"✅ Computed Risk: {risk_calc['risk_label']} (score={risk_calc['risk_score']})")

    print("\n" + "="*50)
    print("📊 FINAL REPORT PREVIEW")
    print("="*50)
    print(final_report)

if __name__ == "__main__":
    main()