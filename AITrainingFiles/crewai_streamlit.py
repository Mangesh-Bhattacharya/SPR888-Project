import streamlit as st
from crewai import Agent, Task, Crew, Process, LLM
from streamlit_lottie import st_lottie
import requests
from datetime import datetime
import pandas as pd
import re
from typing import Type
from crewai.tools import BaseTool
from pydantic import BaseModel, Field
import os
from dotenv import load_dotenv
from urllib.parse import quote

# --- Load environment variables for API keys ---
load_dotenv(dotenv_path="/app/plugins/my_ioc_lookup_tool/.env")
VT_API_KEY = os.getenv("VT_API_KEY")
TF_API_KEY = os.getenv("TF_API_KEY")
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")

# === Streamlit Page Configuration ===
st.set_page_config(
    page_title="Threat Intelligence Report Generator",
    layout="centered"
)

def load_lottieurl(url):
    r = requests.get(url)
    if r.status_code != 200:
        return None
    return r.json()

report_anim = load_lottieurl(
    "https://assets2.lottiefiles.com/packages/lf20_vf7wnpfz.json"
)

st.sidebar.title("Threat Navigation Panel")
selected_page = st.sidebar.radio("Navigate to", ["Input", "Report"])

st.title("🔍 Threat Intelligence Report Generator")
st.markdown(
    """
Analyze suspicious indicators such as IP addresses, domains, file hashes, emails, or actor names 
to generate a detailed, professional-grade threat intelligence report.
"""
)

if "report_text" not in st.session_state:
    st.session_state.report_text = None
if "ioc_input" not in st.session_state:
    st.session_state.ioc_input = None
if "report_date" not in st.session_state:
    st.session_state.report_date = None

# === Utility: Dynamic IoC Type Detection ===
def detect_ioc_type(ioc: str) -> str:
    ip_re = r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"
    hash_re = r"\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b"
    email_re = r"\b\S+@\S+\.\S+\b"
    domain_re = r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b"
    url_re = r"^(http|https)://"

    if re.match(url_re, ioc):
        return "url"
    elif re.match(ip_re, ioc):
        return "ip"
    elif re.match(email_re, ioc):
        return "email"
    elif re.match(hash_re, ioc):
        return "hash"
    elif re.match(domain_re, ioc):
        return "domain"
    else:
        return "attacker_name"

# === Utility: Extract IoCs from text ===
def extract_related_iocs(related_indicators_text):
    ips = set()
    domains = set()
    hashes = set()
    ip_regex = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    domain_regex = r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b'
    hash_regex = r'\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b'
    if not related_indicators_text or related_indicators_text.lower() == "not available.":
        return [], [], []
    for match in re.findall(ip_regex, related_indicators_text):
        if not (match.startswith('127.') or match.startswith('0.') or match == '255.255.255.255'):
            ips.add(match)
    for match in re.findall(hash_regex, related_indicators_text):
        hashes.add(match)
    for match in re.findall(domain_regex, related_indicators_text):
        if not re.match(ip_regex, match):
            domains.add(match)
    return list(ips), list(domains), list(hashes)

# === Streamlit Input Page ===
if selected_page == "Input":
    st.header("Step 1: Enter Indicator of Compromise (IoC)")
    ioc_input = st.text_input("Enter an IoC (IP, domain, hash, email, or attacker name):")
    start_button = st.button("🧠 Start Threat Analysis")

    if start_button and ioc_input:
        st.session_state.ioc_input = ioc_input
        st.session_state.report_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ioc_type = detect_ioc_type(ioc_input)

        st.info("Initializing threat intelligence analysis using multi-agent system...")

        with st.spinner("Running analysis. This may take a few moments..."):
            llm = LLM(
                model="ollama/llama3.2:latest",
                temperature=0.4,
                base_url="http://localhost:11434",
            )

            # --- Input schema for tools ---
            class IoCInput(BaseModel):
                ioc_type: str = Field(..., description="Type of IoC (ip, domain, hash, url, email)")
                ioc_value: str = Field(..., description="Value of the IoC to lookup")

            # --- VirusTotal & ThreatFox Tool ---
            class IoCLookupTool(BaseTool):
                name: str = "IoC Threat Report Tool"
                description: str = (
                    "Fetches threat intelligence reports from VirusTotal and ThreatFox "
                    "based on the provided IoC type and value."
                )
                args_schema: Type[BaseModel] = IoCInput

                def _run(self, ioc_type: str, ioc_value: str) -> str:
                    vt_report = self.query_virustotal(ioc_type.lower(), ioc_value)
                    tf_report = self.query_threatfox(ioc_value)
                    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
                    return (
                        f"\n====== IoC Threat Report ======\n"
                        f"Timestamp: {timestamp}\n"
                        f"IoC Type : {ioc_type}\n"
                        f"IoC Value: {ioc_value}\n\n"
                        f"--- VirusTotal ---\n{vt_report}\n\n"
                        f"--- ThreatFox ---\n{tf_report}\n"
                        f"===============================\n"
                    )

                def query_virustotal(self, ioc_type: str, ioc_value: str) -> str:
                    if not VT_API_KEY:
                        return "VirusTotal API key is missing."
                    try:
                        headers = {"x-apikey": VT_API_KEY}
                        if ioc_type in ["ip", "ips"]:
                            url = f"https://www.virustotal.com/api/v3/ip_addresses/{ioc_value}"
                        elif ioc_type in ["domain", "email"]:
                            url = f"https://www.virustotal.com/api/v3/domains/{ioc_value}"
                        elif ioc_type == "url":
                            encoded = quote(ioc_value, safe="")
                            url = f"https://www.virustotal.com/api/v3/urls/{encoded}"
                        elif ioc_type == "hash":
                            url = f"https://www.virustotal.com/api/v3/files/{ioc_value}"
                        else:
                            return "Unsupported IoC type for VirusTotal."
                        response = requests.get(url, headers=headers, timeout=15)
                        data = response.json().get("data", {}).get("attributes", {})
                        stats = data.get("last_analysis_stats", {})
                        rep = data.get("reputation", "N/A")
                        tags = data.get("tags", [])
                        date = data.get("last_analysis_date", 0)
                        scan_time = datetime.utcfromtimestamp(date).strftime("%Y-%m-%d %H:%M:%S") if date else "N/A"
                        return (
                            f"Last Scan Time  : {scan_time}\n"
                            f"Reputation      : {rep}\n"
                            f"Analysis Stats  : {stats}\n"
                            f"Tags            : {tags}"
                        )
                    except Exception as e:
                        return f"VirusTotal error: {e}"

                def query_threatfox(self, ioc_value: str) -> str:
                    if not TF_API_KEY:
                        return "ThreatFox API key is missing."
                    try:
                        url = "https://threatfox-api.abuse.ch/api/v1/"
                        headers = {"API-KEY": TF_API_KEY}
                        data = {"query": "search_ioc", "search_term": ioc_value}
                        response = requests.post(url, json=data, headers=headers, timeout=15)
                        result = response.json()
                        if result.get("data") and isinstance(result["data"], list):
                            entry = result["data"][0]
                            return (
                                f"Threat Type     : {entry.get('threat_type')}\n"
                                f"Threat Actor    : {entry.get('threat_actor')}\n"
                                f"Malware Family  : {entry.get('malware')}\n"
                                f"Tags            : {', '.join(entry.get('malware_tags', []))}\n"
                                f"Confidence      : {entry.get('confidence_level')}\n"
                                f"First Seen      : {entry.get('first_seen')}\n"
                                f"Reference       : {entry.get('reference')}"
                            )
                        return "No result found in ThreatFox."
                    except Exception as e:
                        return f"ThreatFox error: {e}"

            # --- (Optional) Shodan Tool ---
            class ShodanLookupTool(BaseTool):
                name: str = "Shodan Lookup Tool"
                description: str = "Queries Shodan for IP, domain, or hostname details."
                args_schema: Type[BaseModel] = IoCInput

                def _run(self, ioc_type: str, ioc_value: str) -> str:
                    if not SHODAN_API_KEY:
                        return "Shodan API key is missing."
                    try:
                        # IP lookup
                        if ioc_type == "ip":
                            url = f"https://api.shodan.io/shodan/host/{ioc_value}?key={SHODAN_API_KEY}"
                        # Domain lookup
                        elif ioc_type == "domain":
                            url = f"https://api.shodan.io/dns/domain/{ioc_value}?key={SHODAN_API_KEY}"
                        # Hostname search
                        elif ioc_type == "hostname":
                            url = f"https://api.shodan.io/dns/resolve?hostnames={ioc_value}&key={SHODAN_API_KEY}"
                        else:
                            return "Unsupported IoC type for Shodan."
                        resp = requests.get(url, timeout=15)
                        if resp.status_code == 200:
                            return f"Shodan Data: {resp.text}"
                        else:
                            return f"Shodan error: {resp.text}"
                    except Exception as e:
                        return f"Shodan error: {e}"

            # ---- AGENT SETUP ----
            ioc_tool = IoCLookupTool()
            shodan_tool = ShodanLookupTool()

            researcher = Agent(
                role="Researcher Identity",
                goal="Using the available tools, classify and enrich the IoC using at least 10 safe threat intel sources (VirusTotal, ThreatFox, Shodan, etc.). Gather data for all report sections.",
                backstory="A cyber threat researcher using public sources such as VirusTotal, ThreatFox, Shodan, Hybrid Analysis, etc., without touching the IoC directly.",
                verbose=True,
                tools=[ioc_tool, shodan_tool],
                llm=llm,
            )
            reviewer = Agent(
                role="Reviewer Identity",
                goal="Fact-check and validate all Researcher findings using independent sources and internal knowledge.",
                backstory="A veteran security analyst tasked with verifying IoC intelligence before action.",
                verbose=True,
                llm=llm,
            )
            analyzer = Agent(
                role="Analyzer Identity",
                goal="Analyze the reviewed IoC to determine threat class, actor, attack vector, MITRE mapping, and recommended mitigations.",
                backstory="A senior threat intelligence analyst mapping behavior patterns and guiding defenses.",
                verbose=True,
                llm=llm,
            )
            writer = Agent(
                role="Writer Identity",
                goal="Compile a professional, structured, and client-facing Threat Intelligence Report.",
                backstory="A cybersecurity documentation specialist converting technical findings into actionable, organized reports.",
                verbose=True,
                llm=llm,
            )
            task_classify = Task(
                description=f"Classify the suspected IoC: {ioc_input} as either: IP, file hash, url, email, domain, or attacker name.",
                expected_output="A definitive classification for the suspected IoC.",
                agent=researcher,
            )
            task_research = Task(
                description=f"Conduct threat research on the IoC: {ioc_input}. Use WHOIS, ASN, malware databases, VirusTotal, ThreatFox, Shodan, and others. Include metadata, context, and source citations for all sections. Finish with '[Transitioning to: Reviewer Identity]'",
                expected_output="A comprehensive summary of threat intelligence from at least 10 sources, fully cited.",
                agent=researcher,
            )
            task_review = Task(
                description="Verify all facts and data collected by the Researcher. Remove inaccuracies, highlight confirmed insights. Finish with '[Transitioning to: Analyzer Identity]'",
                expected_output="Cleaned and validated intelligence data set ready for threat analysis.",
                agent=reviewer,
                context=[task_research],
            )
            task_analyze = Task(
                description=f"Perform deep analysis of {ioc_input}. Determine threat classification, confidence (0-100), MITRE ATT&CK mapping, TTPs, likely actors, and defenses. Cover all required report sections. Finish with '[Transitioning to: Writer Identity]'. Bold all section names.",
                expected_output="Full threat context including mapping, impact, and organizational recommendations.",
                agent=analyzer,
                context=[task_review],
            )
            task_write = Task(
                description="Write a formal Threat Intelligence Report with these sections only: 1. Input Summary, 2. Threat Confidence, 3. Key Findings, 4. Quick Assessment, 5. Suspected IoC Core Attributes, 6. Reputation Analysis, 7. Network Behaviour Patterns, 8. Associated Activities, 9. Associated Campaigns, 10. Related Indicators, 11. Detection signatures, 12. Recommendations, 13. Network Controls, 14. Endpoint Protection, 15. References, 16. References Amount. Only bold section names.",
                expected_output="Polished report ready for distribution in the requested format.",
                agent=writer,
                context=[task_analyze],
            )

            crew = Crew(
                agents=[researcher, reviewer, analyzer, writer],
                tasks=[task_research, task_review, task_analyze, task_write],
                process=Process.sequential,
                verbose=True,
            )

            try:
                result = crew.kickoff(inputs={"ioc_input": ioc_input, "ioc_type": ioc_type})
                st.session_state.report_text = str(result)
            except Exception as e:
                st.error(f"Analysis failed: {e}")
            else:
                st.success("✅ Analysis complete! View the report under the 'Report' tab.")

elif selected_page == "Report":
    if report_anim:
        st_lottie(report_anim, height=150, key="report_anim")

    if st.session_state.report_text:
        st.header("📄 Comprehensive Threat Intelligence Report")
        st.caption(f"Report generated: {st.session_state.report_date}")

        report = st.session_state.report_text

        def extract_section(title):
            pattern = rf"\*\*{re.escape(title)}\*\*\n+(.*?)(?=\n\*\*|\Z)"
            match = re.search(pattern, report, re.DOTALL)
            return match.group(1).strip() if match else "Not available."

        threat_conf_match = re.search(r"\*\*Threat Confidence\*\*\s*:?\s*\n?(\d+)", report)
        threat_confidence = int(threat_conf_match.group(1)) if threat_conf_match else None

        input_summary = extract_section("Input Summary")
        key_findings = extract_section("Key Findings")
        quick_assessment = extract_section("Quick Assessment")
        suspected_ioc = extract_section("Suspected IoC Core Attributes")
        reputation_analysis = extract_section("Reputation Analysis")
        network_behavior = extract_section("Network Behaviour Patterns")
        associated_activities = extract_section("Associated Activities")
        associated_campaigns = extract_section("Associated Campaigns")
        related_indicators = extract_section("Related Indicators")
        detection_signatures = extract_section("Detection signatures")
        recommendations = extract_section("Recommendations")
        network_controls = extract_section("Network Controls")
        endpoint_protection = extract_section("Endpoint Protection")
        references = extract_section("References")

        def clean_markdown_text(text):
            text = text.strip()
            text = re.sub(r'\n{2,}', '\n', text)
            text = re.sub(r'^\*\s*', '- ', text, flags=re.MULTILINE)
            text = re.sub(r'\n\*\s*', '\n- ', text)
            return text

        input_summary = clean_markdown_text(input_summary)
        key_findings = clean_markdown_text(key_findings)
        quick_assessment = clean_markdown_text(quick_assessment)
        suspected_ioc = clean_markdown_text(suspected_ioc)
        reputation_analysis = clean_markdown_text(reputation_analysis)
        network_behavior = clean_markdown_text(network_behavior)
        associated_activities = clean_markdown_text(associated_activities)
        associated_campaigns = clean_markdown_text(associated_campaigns)
        related_indicators = clean_markdown_text(related_indicators)
        detection_signatures = clean_markdown_text(detection_signatures)
        recommendations = clean_markdown_text(recommendations)
        network_controls = clean_markdown_text(network_controls)
        endpoint_protection = clean_markdown_text(endpoint_protection)
        references = clean_markdown_text(references)

        with st.expander("🔍 Executive Summary", expanded=True):
            cols = st.columns(3)
            cols[0].metric("Indicator Analyzed", st.session_state.ioc_input)
            cols[1].metric("Threat Confidence", threat_confidence)
            cols[2].metric("Data Sources", "12+ threat feeds")
            st.markdown(f"""
            **Key Findings:**  
            {key_findings}
                        
            **Quick Assessment:**
            {quick_assessment}
            """)

        with st.expander("🕵️ Technical Analysis Details", expanded=True):
            tab1, tab2, tab3 = st.tabs(
                ["Indicator Analysis", "Behavior Patterns", "Defensive Insights"])
            with tab1:
                st.subheader("Indicator Characteristics")
                st.markdown(f"""
                **Core Attributes:**
                {suspected_ioc}
                
                **Reputation Analysis:**
                {reputation_analysis}
                """)
            with tab2:
                st.subheader("Observed Behavior")
                st.markdown(f"""
                **Network Patterns:**
                {network_behavior}
                
                **Associated Activities:**
                {associated_activities}
                """)
            with tab3:
                st.subheader("Defensive Considerations")
                st.markdown(f"""
                **Detection Signatures:**
                {detection_signatures}
                """)

        with st.expander("🌐 Threat Context & References"):
            st.subheader("Related Threat Intelligence")
            st.markdown(f"""
            **Associated Campaigns:**
            {associated_campaigns}
            
            **Similar Indicators:**
            {related_indicators}
            """)
            st.subheader("Reference Materials")
            st.markdown(f"""
            {references}
            """)

        with st.expander("🛡️ Mitigation Strategies"):
            st.subheader("Immediate Actions")
            st.markdown(f"""
            1. **Network Controls:**
                {network_controls}
            
            2. **Endpoint Protection:**
                {endpoint_protection}
            """)
            st.subheader("Long-Term Recommendations")
            st.markdown(f"""
            {recommendations}
            """)

        with st.expander("🔗 Related Indicators of Compromise"):
            ips, domains, hashes = extract_related_iocs(related_indicators)
            ioc_data = []
            for ip in ips:
                ioc_data.append({"Type": "IP", "Value": ip})
            for domain in domains:
                ioc_data.append({"Type": "Domain", "Value": domain})
            for hashval in hashes:
                ioc_data.append({"Type": "Hash", "Value": hashval})
            if not ioc_data:
                st.info("No related IOCs found in this report. Try using a known malicious indicator.")
            else:
                df_iocs = pd.DataFrame(ioc_data)
                st.dataframe(df_iocs)
                st.download_button(
                    label="📥 Download IOCs (CSV)",
                    data=df_iocs.to_csv(index=False),
                    file_name="related_iocs.csv",
                    mime="text/csv"
                )

        st.download_button(
            label="💾 Download Full Report",
            data=st.session_state.report_text,
            file_name="threat_intel_report.txt",
            mime="text/plain",
        )
    else:
        st.warning(
            "No report has been generated yet. Please go to the 'Input' tab and run the analysis.")

