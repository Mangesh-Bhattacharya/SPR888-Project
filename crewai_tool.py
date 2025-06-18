"""threat_intel_pipeline_tool.py
========================================================
A **CrewAI‑compatible tool module** that executes a full 5‑stage threat‑
intelligence pipeline for a given IoC (IP, domain, URL, hash, or email)
 and saves the result to a Markdown report.

Exposed tools
-------------
* **threat_intel_pipeline(ioc_value, ioc_type=None)** – auto‑classifies the
  IoC if *ioc_type* is omitted and runs the pipeline.
* **save_report_md(report_text, ioc)** – writes a Markdown report to disk
  and returns its absolute path.

Quick start
-----------
```bash
pip install crewai crewai-tools langchain
python threat_intel_pipeline_tool.py   # prompts for IoC and runs end‑to‑end
```
"""

from __future__ import annotations
import os
import re
import ipaddress
from datetime import datetime
from typing import Dict, List, Optional

from crewai import Agent, Task, Crew, Process, LLM
from crewai.tools import tool

# ────────────────────────────────────────────────────────────
# 1.  LLM CONFIG
# ────────────────────────────────────────────────────────────

def init_llm(
    model: str = "ollama/llama3.2:latest",
    base_url: str = "http://localhost:11434",
    temperature: float = 0.4,
) -> LLM:
    """Return a pre‑configured LLM (defaults to llama3.2 via Ollama)."""
    return LLM(model=model, base_url=base_url, temperature=temperature)


# ────────────────────────────────────────────────────────────
# 2.  IOC CLASSIFIER  🔍
# ────────────────────────────────────────────────────────────

def guess_ioc_type(ioc: str) -> str:
    """Best‑effort classification of an IoC string.

    Returns one of: ip, hash_md5, hash_sha1, hash_sha256, email, url, domain,
    unknown."""
    # 1️⃣ IP address (IPv4 or IPv6)
    try:
        ipaddress.ip_address(ioc)
        return "ip"
    except ValueError:
        pass

    # 2️⃣ Hashes (length‑based heuristics)
    if re.fullmatch(r"[A-Fa-f0-9]{32}", ioc):
        return "hash_md5"
    if re.fullmatch(r"[A-Fa-f0-9]{40}", ioc):
        return "hash_sha1"
    if re.fullmatch(r"[A-Fa-f0-9]{64}", ioc):
        return "hash_sha256"

    # 3️⃣ Email address
    if re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", ioc):
        return "email"

    # 4️⃣ URL (very loose regex)
    if re.fullmatch(r"https?://[^\s]+", ioc):
        return "url"

    # 5️⃣ Domain (contains a dot & no scheme)
    if "." in ioc and " " not in ioc:
        return "domain"

    return "unknown"


# ────────────────────────────────────────────────────────────
# 3.  AGENTS
# ────────────────────────────────────────────────────────────

def build_agents(llm: LLM) -> Dict[str, Agent]:
    return {
        "researcher": Agent(
            role="Researcher",
            goal="Collect threat‑intel from ≥10 open sources",
            backstory="OSINT hunter using VT, ThreatFox, Shodan, etc.",
            verbose=True,
            llm=llm,
        ),
        "reviewer": Agent(
            role="Reviewer",
            goal="Fact‑check research and remove inaccuracies",
            backstory="Senior intel QA specialist",
            verbose=True,
            llm=llm,
        ),
        "analyzer": Agent(
            role="Analyzer",
            goal="Classify threat, map MITRE ATT&CK & propose mitigations",
            backstory="Threat‑intel analyst correlating TTPs and defences",
            verbose=True,
            llm=llm,
        ),
        "writer": Agent(
            role="Writer",
            goal="Compose a 1000‑word structured threat report",
            backstory="Security documentation expert",
            verbose=True,
            llm=llm,
        ),
        "publisher": Agent(
            role="Publisher",
            goal="Save the report as Markdown",
            backstory="Automation agent exporting documents",
            verbose=False,
            llm=llm,
        ),
    }


# ────────────────────────────────────────────────────────────
# 4.  TOOL: Markdown Saver
# ────────────────────────────────────────────────────────────

@tool("save_report_md")
def save_report_md(report_text: str, ioc: str) -> str:
    """Write *report_text* to `Threat_Intel_Report_<ioc>_<ts>.md` and return path."""
    safe_ioc = re.sub(r"[^A-Za-z0-9_.-]", "_", ioc)
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    filename = f"Threat_Intel_Report_{safe_ioc}_{ts}.md"
    with open(filename, "w", encoding="utf-8") as fh:
        fh.write(report_text)
    return os.path.abspath(filename)


# ────────────────────────────────────────────────────────────
# 5.  TASK SEQUENCE
# ────────────────────────────────────────────────────────────

def build_tasks(ioc: str, ioc_type: str, agents: Dict[str, Agent]) -> List[Task]:
    """Create the 5‑task workflow wired with appropriate context."""

    t1 = Task(
        description=(
            f"Gather OSINT on {ioc_type.upper()} **{ioc}** from ≥10 sources "
            "(VirusTotal, ThreatFox, Hybrid‑Analysis, Censys, AbuseIPDB, etc.).\n"
            "Include WHOIS/registrar, detection stats, sandbox verdicts, actor notes.\n"
            "Finish with **[Transitioning to: Reviewer]**"
        ),
        expected_output="Intel from ≥10 sources.",
        agent=agents["researcher"],
    )

    t2 = Task(
        description=(
            "Validate every statement from the researcher, correct inaccuracies, "
            "remove unverifiable items.\n"
            "Finish with **[Transitioning to: Analyzer]**"
        ),
        expected_output="Clean, fact‑checked intel.",
        agent=agents["reviewer"],
        context=[t1],
    )

    t3 = Task(
        description=(
            f"Analyze verified intel for **{ioc}**. Determine threat family, "
            "related campaigns, MITRE ATT&CK mapping and mitigations.\n"
            "Finish with **[Transitioning to: Writer]**"
        ),
        expected_output="Analysis with ATT&CK mapping & mitigations.",
        agent=agents["analyzer"],
        context=[t2],
    )

    t4 = Task(
        description=(
            "Draft a structured report (≥1000 words) with sections:\n"
            "1. Input Summary\n2. Threat Classification\n3. Tool‑Data Summary\n"
            "4. Web‑Search Intelligence\n5. IoC Correlation & Analysis\n"
            "6. Mitigation & Detection Recommendations\n7. Appendix / References\n\n"
            "Use clear headings and bullet lists.\n"
            "Finish with **[Transitioning to: Publisher]**"
        ),
        expected_output="Complete Markdown threat‑intel report.",
        agent=agents["writer"],
        context=[t3],
    )

    t5 = Task(
        description="Use *save_report_md* with {report_text, ioc} to save the report and return the absolute path.",
        expected_output="Absolute path of the .md file.",
        agent=agents["publisher"],
        context=[t4],
        tools=[save_report_md],
    )

    return [t1, t2, t3, t4, t5]


# ────────────────────────────────────────────────────────────
# 6.  PIPELINE EXECUTION LOGIC
# ────────────────────────────────────────────────────────────

def _run_pipeline(ioc_value: str, ioc_type: Optional[str] = None) -> str:
    """Internal helper that spins up agents, tasks, and runs CrewAI."""
    if not ioc_type:
        ioc_type = guess_ioc_type(ioc_value)

    llm    = init_llm()
    agents = build_agents(llm)
    tasks  = build_tasks(ioc_value, ioc_type, agents)

    crew = Crew(
        agents=list(agents.values()),
        tasks=tasks,
        process=Process.sequential,
        verbose=True,
    )

    return crew.kickoff(inputs={
        "ioc_input": ioc_value,
        "ioc_type": ioc_type,
    })


# ────────────────────────────────────────────────────────────
# 7.  EXPOSED TOOLS
# ────────────────────────────────────────────────────────────

@tool("threat_intel_pipeline")
def threat_intel_pipeline(ioc_value: str, ioc_type: str | None = None) -> str:
    """Run the full pipeline; auto‑classifies *ioc_type* if omitted."""
    return _run_pipeline(ioc_value, ioc_type)


# Plain callable for CLI/debug usage

def run_pipeline(ioc_value: str, ioc_type: str | None = None) -> str:
    return _run_pipeline(ioc_value, ioc_type)


# ────────────────────────────────────────────────────────────
# 8.  CLI ENTRY POINT
# ────────────────────────────────────────────────────────────

if __name__ == "__main__":
    _ioc = input("Enter IoC (IP, domain, hash, email, or URL): ").strip()
    try:
        out_path = run_pipeline(_ioc)
        print("\n✅ Report saved:", out_path)
    except Exception as exc:
        print("\n⚠️  Pipeline failed:", exc)
