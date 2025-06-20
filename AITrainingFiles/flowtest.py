import streamlit as st
from crewai import Agent, Task, Crew, Process, LLM
from streamlit_lottie import st_lottie
import requests
from datetime import datetime
import pandas as pd
import re
from typing import Type
from crewai.tools import BaseTool
from crewai_tools import WebsiteSearchTool, SerperDevTool
from crewai.knowledge.source.string_knowledge_source import StringKnowledgeSource
from pydantic import BaseModel, Field
import os
from dotenv import load_dotenv
import webbrowser
from urllib.parse import quote
from bs4 import BeautifulSoup
import urllib.robotparser
from urllib.parse import quote, urlparse


# === Streamlit Page Configuration ===
st.set_page_config(
    page_title="Threat Intelligence Report Generator",
    layout="centered"
)

# === Load Lottie Animation ===


def load_lottieurl(url):
    r = requests.get(url)
    if r.status_code != 200:
        return None
    return r.json()


report_anim = load_lottieurl(
    "https://assets2.lottiefiles.com/packages/lf20_vf7wnpfz.json"
)

# === Sidebar Navigation ===
st.sidebar.title("Threat Navigation Panel")
selected_page = st.sidebar.radio("Navigate to", ["Input", "Report"])

# === Main Title and Description ===
st.title("🔍 Threat Intelligence Report Generator")
st.markdown(
    """
Analyze suspicious indicators such as IP addresses, domains, file hashes, emails, or actor names 
to generate a detailed, professional-grade threat intelligence report.
"""
)

# === Initialize Session State ===
if "report_text" not in st.session_state:
    st.session_state.report_text = None
if "ioc_input" not in st.session_state:
    st.session_state.ioc_input = None
if "report_date" not in st.session_state:
    st.session_state.report_date = None

# === INPUT PAGE ===
if selected_page == "Input":
    st.header("Step 1: Enter Indicator of Compromise (IoC)")
    ioc_input = st.text_input(
        "Enter an IoC (IP, domain, hash, email, or attacker name):"
    )
    start_button = st.button("🧠 Start Threat Analysis")

    if start_button and ioc_input:
        st.session_state.ioc_input = ioc_input
        st.session_state.report_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        st.info("Initializing threat intelligence analysis using multi-agent system...")

        with st.spinner("Running analysis. This may take a few moments..."):
            # === Configure Language Model ===
            llm = LLM(
                model="ollama/llama3.2:latest",
                temperature=0.2,
                base_url="http://localhost:11434",
            )
            # === Tool Definition ===
            # === ThreatFox Queries ===
            def query_threatfox(ioc_type: str, ioc_value: str) -> str:
                tf_api_key = os.getenv("TF_API_KEY")
                if not tf_api_key:
                    raise ValueError("ThreatFox API Key not found in environment variables.")

                url = "https://threatfox-api.abuse.ch/api/v1/"
                headers = {"API-KEY": tf_api_key}  # Corrected header
                data = {"query": "search_ioc", "search_term": ioc_value, "exact_match": False}

                try:
                    response = requests.post(url, headers=headers, json=data)
                    result = response.json()

                    if result.get("query_status") == "ok" and result.get("data"):
                        entries = result["data"]
                        if isinstance(entries, list) and len(entries) > 0:
                            entry = entries[0]
                            malware_samples = entry.get("malware_samples", [])
                            sample_output = ""
                            for sample in malware_samples:
                                sample_output += (
                                    f"  - Time: {sample.get('time_stamp')}\n"
                                    f"    MD5 : {sample.get('md5_hash')}\n"
                                    f"    SHA256: {sample.get('sha256_hash')}\n"
                                    f"    Link: {sample.get('malware_bazaar')}\n"
                                )

                            return (
                                f"IoC               : {entry.get('ioc', 'N/A')}\n"
                                f"Threat Type       : {entry.get('threat_type', 'N/A')} ({entry.get('threat_type_desc', '')})\n"
                                f"IoC Type          : {entry.get('ioc_type', 'N/A')} ({entry.get('ioc_type_desc', '')})\n"
                                f"Malware           : {entry.get('malware_printable', 'N/A')} ({entry.get('malware', '')})\n"
                                f"Aliases           : {entry.get('malware_alias', 'N/A')}\n"
                                f"Malpedia Link     : {entry.get('malware_malpedia', 'N/A')}\n"
                                f"Confidence Level  : {entry.get('confidence_level', 'N/A')}\n"
                                f"First Seen        : {entry.get('first_seen', 'N/A')}\n"
                                f"Last Seen         : {entry.get('last_seen', 'N/A')}\n"
                                f"Reference         : {entry.get('reference', 'N/A')}\n"
                                f"Reporter          : {entry.get('reporter', 'N/A')}\n"
                                f"Tags              : {entry.get('tags', 'N/A')}\n"
                                f"\nRelated Malware Samples:\n{sample_output if sample_output else '  None'}"
                            )
                        else:
                            return f"No entries found in ThreatFox for this IoC. Full response:\n{result}"
                    else:
                        return f"Query not successful or no data. Full response:\n{result}"
                except Exception as e:
                    return f"Error querying ThreatFox: {e}"

            # === VirusTotal Queries ===
            def query_virustotal(ioc_type: str, ioc_value: str) -> str:
                vt_api_key = os.getenv("VT_API_KEY")
                if not vt_api_key:
                    raise ValueError("VirusTotal API Key not found in environment variables.")

                if ioc_type == "ip":
                    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ioc_value}"
                elif ioc_type == "domain":
                    url = f"https://www.virustotal.com/api/v3/domains/{ioc_value}"
                elif ioc_type == "hash":
                    url = f"https://www.virustotal.com/api/v3/files/{ioc_value}"
                else:
                    return "Unsupported IoC type for VirusTotal."

                headers = {"accept": "application/json", "x-apikey": vt_api_key}
                response = requests.get(url, headers=headers)

                if response.status_code != 200:
                    return f"Error {response.status_code}: {response.text}"

                data = response.json().get("data", {}).get("attributes", {})
                stats = data.get("last_analysis_stats", {})
                reputation = data.get("reputation", "N/A")
                analysis_results = data.get("last_analysis_results", {})

                total = sum(stats.values())
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                harmless = stats.get("harmless", 0)
                undetected = stats.get("undetected", 0)

                flagged_engines = [f"{engine}: {res.get('result')}" for engine, res in analysis_results.items() if res.get("category") in ("malicious", "suspicious")]

                return (
                    f"Detection Ratio: {malicious + suspicious}/{total} (Malicious: {malicious}, Suspicious: {suspicious}, Harmless: {harmless}, Undetected: {undetected})\n"
                    f"Reputation: {reputation}\n"
                    f"Flagged by: {', '.join(flagged_engines) if flagged_engines else 'None'}"
                )

            # === Classifier and Aggregator ===
            def classifier(ioc: str) -> str:
                ioc = ioc.strip()
                ip_pattern = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
                hash_pattern = re.compile(r"^[a-fA-F0-9]{32,64}$")
                domain_pattern = re.compile(r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$")

                result_log = []

                if ip_pattern.match(ioc):
                    result_log.append("Detected IP address.")
                    result_log.append("--- VirusTotal ---")
                    result_log.append(query_virustotal("ip", ioc))
                    result_log.append("--- ThreatFox ---")
                    result_log.append(query_threatfox("ip", ioc))

                elif hash_pattern.match(ioc):
                    result_log.append("Detected file hash.")
                    result_log.append("--- VirusTotal ---")
                    result_log.append(query_virustotal("hash", ioc))
                    result_log.append("--- ThreatFox ---")
                    result_log.append(query_threatfox("hash", ioc))

                elif domain_pattern.match(ioc):
                    result_log.append("Detected domain.")
                    result_log.append("--- VirusTotal ---")
                    result_log.append(query_virustotal("domain", ioc))
                    result_log.append("--- ThreatFox ---")
                    result_log.append(query_threatfox("domain", ioc))

                else:
                    result_log.append("Unsupported IoC type or format.")

                return "\n".join(result_log)
            tool_results = (classifier(ioc_input))
            #print(tool_results)
            tool_output = StringKnowledgeSource(content=tool_results)
            # print("PRINTING KNOWLEDGE SOURCE")
            # print(tool_output)
            # tool_output.storage = storage
            # tool_output.add()
            report_template = """
            ** Input Summary **
            <To be filled>

            ** Threat Confidence **
            <To be filled>

            ** Key Findings **
            <To be filled>

            ** Quick Assessment **
            <To be filled>

            ** Suspected IoC Core Attributes **
            <To be filled>

            ** Reputation Analysis **
            <To be filled>

            ** Network Behaviour Patterns **
            <To be filled>

            ** Associated Activities **
            <To be filled>

            ** Associated Campaigns **
            <To be filled>

            ** Related Indicators **
            <To be filled>

            ** Detection signatures **
            <To be filled>

            ** Recommendations **
            <To be filled>

            ** Network Controls **
            <To be filled>

            ** Endpoint Protection **
            <To be filled>

            ** References **
            <To be filled>
            """

            template = StringKnowledgeSource(content=report_template)

            # === Web Search Tool Definition ===
            websearch_tool = WebsiteSearchTool()
            search_tool = SerperDevTool(n_results=10)
            USER_AGENT = "Mozilla/5.0"

            def is_allowed_to_scrape(url, user_agent=USER_AGENT):
                try:
                    parsed_url = urlparse(url)
                    robots_url = f"{parsed_url.scheme}://{parsed_url.netloc}/robots.txt"
                    rp = urllib.robotparser.RobotFileParser()
                    rp.set_url(robots_url)
                    rp.read()
                    return rp.can_fetch(user_agent, url)
                except Exception:
                    return False  # Be cautious by default

            def scrape_with_requests(url):
                try:
                    headers = {
                        "User-Agent": USER_AGENT
                    }
                    response = requests.get(url, headers=headers, timeout=10)
                    response.raise_for_status()
                    soup = BeautifulSoup(response.text, "html.parser")
                    title = soup.title.string.strip() if soup.title else "No Title"
                    paragraphs = soup.find_all("p")
                    text = " ".join(p.get_text().strip() for p in paragraphs)
                    summary = " ".join(text.split()[:300])  # ~300 word summary
                    return {"title": title, "summary": summary}
                except Exception as e:
                    return {"title": "Error", "summary": f"Could not scrape {url}: {e}"}

            def search_google_cse(query, max_results=2):
                GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")
                GOOGLE_CX = os.getenv("GOOGLE_CX")
                url = "https://www.googleapis.com/customsearch/v1"
                params = {
                    "key": GOOGLE_API_KEY,
                    "cx": GOOGLE_CX,
                    "q": query,
                    "num": max_results,
                }
                try:
                    response = requests.get(url, params=params)
                    items = response.json().get("items", [])
                    return [(item.get("title", "No Title"), item.get("link")) for item in items]
                except Exception:
                    return []

            def extract_and_search(input_text):
                search_terms = []

                # Extract Malware
                malware_match = re.search(r"Malware\s+:\s+([^\n(]+)", input_text)
                if malware_match:
                    search_terms.append(malware_match.group(1).strip())

                # Extract Aliases
                aliases_match = re.search(r"Aliases\s+:\s+([^\n]+)", input_text)
                if aliases_match:
                    aliases = [alias.strip() for alias in aliases_match.group(1).split(",")]
                    search_terms.extend(aliases)

                # Extract Tags
                tags_match = re.search(r"Tags\s+:\s+\[([^\]]+)\]", input_text)
                if tags_match:
                    tags = [tag.strip().strip("'\"") for tag in tags_match.group(1).split(",")]
                    search_terms.extend(tags)

                # Extract hashes (MD5, SHA256)
                hash_matches = re.findall(r"(MD5|SHA256)\s*:\s*([a-fA-F0-9]{32,64})", input_text)
                for _, hash_val in hash_matches:
                    search_terms.append(f"hash {hash_val}")

                # Deduplicate
                search_terms = list(set(search_terms))

                output = "🔍 Top Search Results (robots.txt respected):\n"
                for term in search_terms:
                    search_results = search_google_cse(term)
                    if not search_results:
                        continue

                    summaries = ""
                    for title, link in search_results:
                        if not link or not is_allowed_to_scrape(link):
                            continue

                        scrape_result = scrape_with_requests(link)
                        summaries += f"- [{scrape_result['title']}]({link})\n  • {scrape_result['summary'][:300]}...\n"

                    if summaries:
                        output += f"\n🔹 **{term}**\n{summaries}"

                return output.strip()

            search_results = str(extract_and_search(tool_results))
            print("Printing SEARCH RESULTS     ",search_results)
            search_output = StringKnowledgeSource(content=search_results)

            # === Agents ===
            researcher = Agent(
                role="Threat Intelligence Researcher",
                goal=(
                    "Extract all necessary from knowledge and the search tool results threat intelligence to populate every section of the final report, "
                    "including IoC metadata, detection rates, behavior, and context. Ensure every detail needed "
                    "for the following sections is collected: Input Summary, Threat Confidence, Key Findings, "
                    "Quick Assessment, Core Attributes, Reputation Analysis, Network Behaviour, Related Indicators, Campaigns, and Detection Signatures. "
                    "Make sure to strip any unrelated to cybersecurity threat information."
                ),
                backstory="Specializes in structured threat data analysis using internal intelligence reports only.",
                verbose=True,
                knowledge_sources=[search_output, tool_output, template],
                llm=llm,
            )

            fact_checker = Agent(
            role="Threat Intelligence Validator",
            goal=(
                "Execute layered verification of all extracted threat intelligence by conducting web search and verifying the information obtained by researcher. Tasks include: "
                "1) Cross-checking extracted values against multiple external trusted sources, "
                "2) Validating internal consistency (e.g., reputation scores vs. engine flags), "
                "3) Confirming timeline logic (e.g., first seen dates align with reported campaigns), and "
                "4) Verifying that all listed data aligns with known threat actor behaviors and malware characteristics."
            ),
            backstory=(
                "An experienced cyber threat validation expert combining open-source research skills with analytical consistency checking. "
                "Uses online intelligence sources to confirm threat signatures, uncover contradictions, and ensure timestamp and reputation accuracy across all report fields."),
            knowledge_sources=[template],
            verbose=True,
            llm=llm,
            )

            analyzer = Agent(
                role="Cyber Threat Analyst",
                goal=(
                "Correlate all verified intelligence into structured, actionable threat conclusions that align with best practices in threat analysis. "
                "For each report section, assess and interpret the relevance, severity, and implications of the data. "
                "Incorporate: threat confidence scoring with justification, MITRE ATT&CK technique and tactic mappings, behavioral indicators, "
                "campaign attribution (if applicable), attacker infrastructure use, and impact on confidentiality, integrity, and availability (CIA). Define Threat Confidence as just number (0-100)- don't provide any other text for this header "
                "Conclude with defensive insights to guide detection, prevention, and response strategies."),
                backstory="Analyzes and contextualizes threat reports to produce actionable threat intelligence summaries.",
                verbose=True,
                knowledge_sources=[tool_output, template],
                llm=llm,
            )

            writer = Agent(
                role="Threat Report Writer",
                goal=(
                    "Using the provided template from knowledge, compile the threat report using the information obtained from other agents. "
                    "Each section must be completed thoroughly using only verified and analyzed data obtained from Researcher and Analyzer. Do not create new headers and make sure to use the headers from template verbatim, no numbering."
                ),
                backstory="Produces professional-grade threat reports with clear formatting and no deviation from structure represented in the template from the knowledge.",
                verbose=True,
                knowledge_sources=[template],
                llm=llm,
            )

            # === Tasks ===
            task_research = Task(
                description=(
                    "Extract all threat intelligence details from the knowledge base to support every section of the template. "
                    "This includes IoC attributes, malware names, detection rates, first seen timestamps, aliases, threat type, and external links, information obtained from the search."
                ),
                expected_output="Comprehensive structured threat data aligned to report sections.",
                agent=researcher
            )

            task_fact_check = Task(
                description=(
                    "Fact-check the extracted intelligence using external sources. Confirm or refute all key fields including malware family, tags, threat type, and detection engines."
                ),
                expected_output="Fully verified set of threat intelligence ready for analytical correlation.",
                agent=fact_checker,
                context=[task_research]
            )

            task_analyze = Task(
                description=(
                    "Analyze and interpret verified threat intelligence. Produce full context for each report section including Threat Confidence score, attacker behavior, campaign links, and detection patterns."
                ),
                expected_output="Full analytical context mapped to the template’s required report sections.",
                agent=analyzer,
                context=[task_fact_check]
            )

            task_write = Task(
                description=(
                    "Use the strict template provided in your knowledge to write a complete professional threat report. "
                    "Only use headers from the template. Populate each section thoroughly and accurately using the Analyzer’s and Researcher's validated outputs."
                    "If you report has bullet points make sure they are converted to 1) 2) 3)"
                ),
                expected_output= "Report strictly following the headers from the template with no numbering, verbatim.",
                agent=writer,
                context=[task_analyze]
            )

            task_confirm_write = Task(
                    description=(
                        "Confirm that the report provided by writer strictly follows the header structure presented in the template from the knowledge verbatim. Make sure no other headers are used, make sure value of threat confidence header is just the number from 0-100. If other structure than the template is detected, make sure to apply the headers from the report to the information provided."
                        "If you report values has bullet points make sure they are converted to 1) 2) 3)"
                        "If the headers fo by 1. 2. 3. make sure to remove the numbering, leaving only headers verabtim to the template"),
                    expected_output="Finalized threat report containing exact headers from the template from the knowledge, fully completed and confirmed. Threat confidence header should have only value of 0-100 number and no other text.",
                    agent=writer,
                    context=[task_analyze]
                )

            # === Assemble and Execute Crew ===
            crew = Crew(
                agents=[researcher, fact_checker, analyzer, writer],
                tasks=[task_research, task_fact_check, task_analyze, task_write, task_confirm_write],
                process=Process.sequential,
                verbose=True,
                memory=False
            )

            result = crew.kickoff(
                inputs={"ioc_input": ioc_input})
            st.session_state.report_text = str(result)
            print("Here's the report state result: "+st.session_state.report_text)
        st.success("✅ Analysis complete! View the report under the 'Report' tab.")

# === REPORT PAGE ===
elif selected_page == "Report":
    if report_anim:
        st_lottie(report_anim, height=150, key="report_anim")

    if st.session_state.report_text:
        st.header("📄 Comprehensive Threat Intelligence Report")
        st.caption(f"Report generated: {st.session_state.report_date}")

        import re
        report = st.session_state.report_text

        def extract_section(title):
            pattern = rf"\*\*\s*{re.escape(title)}\s*\*\*\s*\n+(.*?)(?=\n\*\*|\Z)"
            match = re.search(pattern, report, re.DOTALL)
            return match.group(1).strip() if match else "Not available."

        # Extract threat confidence
        threat_conf_match = re.search(r"\*\*\s*Threat Confidence\s*\*\*\s*:?\s*\n?(\d+)", report)
        threat_confidence = int(threat_conf_match.group(1)) if threat_conf_match else None

        # Extract all report sections
        sections = {title: extract_section(title) for title in [
            "Input Summary", "Threat Confidence", "Key Findings", "Quick Assessment",
            "Suspected IoC Core Attributes", "Reputation Analysis", "Network Behaviour Patterns",
            "Associated Activities", "Associated Campaigns", "Related Indicators",
            "Detection signatures", "Recommendations", "Network Controls", "Endpoint Protection", "References"
        ]}

        # === Report Overview ===
        with st.expander("🔍 Executive Summary", expanded=True):
            cols = st.columns(3)
            cols[0].metric("Indicator Analyzed", st.session_state.ioc_input)
            cols[1].metric("Threat Confidence", threat_confidence)
            cols[2].metric("Data Sources", "AI + OSINT verified")

            st.markdown(f"""
            **Key Findings:**  
            {sections['Key Findings']}

            **Quick Assessment:**  
            {sections['Quick Assessment']}
            """)

        # === Technical Analysis ===
        with st.expander("🕵️ Technical Analysis Details", expanded=True):
            tab1, tab2, tab3 = st.tabs(["Indicator Analysis", "Behavior Patterns", "Defensive Insights"])

            with tab1:
                st.subheader("Indicator Characteristics")
                st.markdown(f"""
                **Input Summary:**  
                {sections['Input Summary']}

                **Core Attributes:**  
                {sections['Suspected IoC Core Attributes']}

                **Reputation Analysis:**  
                {sections['Reputation Analysis']}
                """)

            with tab2:
                st.subheader("Observed Behavior")
                st.markdown(f"""
                **Network Behaviour Patterns:**  
                {sections['Network Behaviour Patterns']}

                **Associated Activities:**  
                {sections['Associated Activities']}

                **Associated Campaigns:**  
                {sections['Associated Campaigns']}
                """)

            with tab3:
                st.subheader("Defensive Considerations")
                st.markdown(f"""
                **Detection Signatures:**  
                {sections['Detection signatures']}

                **Network Controls:**  
                {sections['Network Controls']}

                **Endpoint Protection:**  
                {sections['Endpoint Protection']}
                """)

        # === Context and Recommendations ===
        with st.expander("🌐 Threat Context & References"):
            st.subheader("Related Indicators")
            st.markdown(f"{sections['Related Indicators']}")

            st.subheader("References")
            st.markdown(f"{sections['References']}")

        with st.expander("🛡️ Recommendations & Mitigations"):
            st.markdown(f"{sections['Recommendations']}")
        # === IOCs ===
        with st.expander("🔗 Related Indicators of Compromise"):
            ioc_data = {
                "Type": ["IP", "Domain", "Hash"],
                "Value": [st.session_state.ioc_input, "malicious.example.com", "a1b2c3d4e5f6..."],
                "First Seen": ["2023-01-15", "2023-03-22", "2023-05-10"],
                "Confidence": ["High", "Medium", "High"]
            }
            st.dataframe(ioc_data)

            st.download_button(
                label="📥 Download IOCs (CSV)",
                data=pd.DataFrame(ioc_data).to_csv(index=False),
                file_name="related_iocs.csv",
                mime="text/csv"
            )

        # === Full Report Download ===
        st.download_button(
            label="💾 Download Full Report",
            data=st.session_state.report_text,
            file_name="threat_intel_report.txt",
            mime="text/plain",
        )
    else:
        st.warning(
            "No report has been generated yet. Please go to the 'Input' tab and run the analysis.")
            