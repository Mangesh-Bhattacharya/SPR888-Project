import os
import re
import requests
import streamlit as st
import chardet
import ipaddress
from datetime import datetime, timedelta
from streamlit_lottie import st_lottie
from crewai import Agent, Task, Crew, Process, LLM
from crewai.knowledge.source.string_knowledge_source import StringKnowledgeSource
from dotenv import load_dotenv
import pandas as pd
from bs4 import BeautifulSoup
import urllib.robotparser
from urllib.parse import urlparse
import json
import hashlib
import warnings
from typing import Dict, List, Optional, Tuple
from io import BytesIO
import zipfile

# Suppress warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)

# Load environment variables
load_dotenv()

# === Constants ===
MAX_REPORT_AGE_DAYS = 7
DATA_FRESHNESS_THRESHOLD = timedelta(days=14)
USER_AGENT = "Mozilla/5.0"
DATASET_PATH = r"C:\Users\mrfol.ABS-PC\Documents\GitHub\SPR888-Project\Datasets"

# Navigation State Management
pages = ["Single IOC Analysis", "Multiple IOC Analysis", "Report"]
if "selected_page" not in st.session_state:
    st.session_state.selected_page = pages[0]
if "nav_to_page" not in st.session_state:
    st.session_state["nav_to_page"] = None

if st.session_state.get("nav_to_page") in pages:
    st.session_state.selected_page = st.session_state.nav_to_page
    st.session_state.nav_to_page = None
    st.rerun()

# Page Config & CSS
st.set_page_config(
    page_title="Multiple IOC Threat Intelligence Analyzer", 
    layout="centered",
    initial_sidebar_state="expanded"
)

st.markdown("""
<style>
    .stApp {
        background-color: #0f1115;
    }
    .stButton>button {
        background-color: #007bff;
        color: white;
        border-radius: 5px;
        padding: 10px 20px;
    }
    .stButton>button:hover {
        background-color: #0056b3;
    }
    .stTextInput>div>input {
        border-radius: 5px;
        padding: 10px;
    }
    .stTextArea>div>textarea {
        border-radius: 5px;
        padding: 10px;
    }
    .stSelectbox>div>div>div>select {
        border-radius: 5px;
        padding: 10px;
    }
    .stFileUploader>div>input {
        border-radius: 5px;
        padding: 10px;
    }
</style>
""", unsafe_allow_html=True)

# Session State Defaults
for key, val in {
    "ioc_list": [],
    "analysis_complete": False,
    "individual_reports": {},  # Store individual reports
    "selected_ioc_report": None,  # For dropdown selection
    "tool_results": None,  # Store raw tool results
    "batch_zip": None,  # For batch download
    "filtered_iocs": [],  # Track IOCs that were filtered out
    "private_iocs": []  # Track private IOCs that were skipped
}.items():
    if key not in st.session_state:
        st.session_state[key] = val

# === Utility Functions ===
def load_lottieurl(url: str) -> Optional[dict]:
    try:
        r = requests.get(url, timeout=10)
        return r.json() if r.status_code == 200 else None
    except Exception:
        return None

# Formatting Helpers
def format_key_findings(text):
    lines = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if re.match(r"^\d+\)", stripped):
            lines.append(stripped)
        elif re.match(r"^\d+\.", stripped):
            lines.append(stripped.replace(".", ")", 1))
        elif re.match(r"^[-•*]", stripped):
            lines.append(stripped[1:].strip())
        else:
            lines.append(stripped)
    if lines:
        markdown = "\n".join([f"{idx+1}. {line.lstrip('1234567890). ')}" for idx, line in enumerate(lines)])
        return markdown
    return ""

def format_related_indicators(text):
    items = [line.strip() for line in text.splitlines() if line.strip()]
    clean_items = []
    for line in items:
        line = re.sub(r"^\s*(\d+[\.\)]\s*)+", "", line)
        clean_items.append(line)
    return "\n".join([f"{idx+1}. {item}" for idx, item in enumerate(clean_items)])

def detect_ioc_type(ioc: str) -> Tuple[str, str]:
    """Enhanced IOC type detection using ipaddress module for IP validation"""
    ioc = ioc.strip()
    
    # Try IPv4 first
    try:
        ipaddress.IPv4Address(ioc)
        return ("IPv4 Address", "Network")
    except ipaddress.AddressValueError:
        pass
    
    # Try IPv6 next
    try:
        ipaddress.IPv6Address(ioc)
        return ("IPv6 Address", "Network")
    except ipaddress.AddressValueError:
        pass
    
    # Domain Pattern
    domain_pattern = r'^(?!-)[a-zA-Z0-9-]{1,63}(?<!-)(\.[a-zA-Z0-9-]{1,63}(?<!-))*\.[a-zA-Z]{2,63}$'
    if re.match(domain_pattern, ioc):
        return ("Domain Name", "Network")
    
    # Hash Patterns
    md5_pattern = r'^[a-fA-F0-9]{32}$'
    if re.match(md5_pattern, ioc):
        return ("MD5 Hash", "File")
    
    sha1_pattern = r'^[a-fA-F0-9]{40}$'
    if re.match(sha1_pattern, ioc):
        return ("SHA-1 Hash", "File")
    
    sha256_pattern = r'^[a-fA-F0-9]{64}$'
    if re.match(sha256_pattern, ioc):
        return ("SHA-256 Hash", "File")
    
    return ("Unknown", "Uncategorized")

def is_private_ioc(ioc: str) -> bool:
    """Check if an IOC is private/localhost"""
    ioc = ioc.strip().lower()
    
    # Check for localhost domains
    if ioc in ["localhost", "127.0.0.1", "::1", "0.0.0.0"]:  # nosec B104 -- string comparison, not a socket bind
        return True
        
    # Check for .local domains
    if ioc.endswith(".localhost") or ioc.endswith(".local"):
        return True
        
    # Check for private IP ranges
    try:
        ip = ipaddress.ip_address(ioc)
        if ip.is_private or ip.is_loopback:
            return True
    except:
        pass
        
    # Check for localhost in URLs
    if "localhost" in ioc or "127.0.0.1" in ioc:
        return True
        
    # Check for private network IPs in URLs
    try:
        parsed = urlparse(ioc)
        host = parsed.hostname or ioc
        try:
            ip = ipaddress.ip_address(host)
            if ip.is_private or ip.is_loopback:
                return True
        except:
            if "localhost" in host or host.endswith(".local"):
                return True
    except:
        pass
        
    return False

def search_local_datasets(ioc_value: str) -> Dict:
    """Search all local dataset files for the IOC with detailed context"""
    results = {
        "matches": [],
        "total_occurrences": 0,
        "datasets_searched": 0,
        "error": None
    }
    
    try:
        for root, _, files in os.walk(DATASET_PATH):
            for file in files:
                results["datasets_searched"] += 1
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                        for line_num, line in enumerate(f, 1):
                            if ioc_value.lower() in line.lower():
                                # Get 2 lines before and after for context
                                context_lines = []
                                with open(file_path, "r", encoding="utf-8", errors="ignore") as f_context:
                                    all_lines = f_context.readlines()
                                    start = max(0, line_num-3)
                                    end = min(len(all_lines), line_num+2)
                                    context_lines = all_lines[start:end]
                                
                                match = {
                                    "dataset_name": os.path.splitext(file)[0],
                                    "file_name": file,
                                    "file_path": os.path.relpath(file_path, DATASET_PATH),
                                    "line_number": line_num,
                                    "line_content": line.strip(),
                                    "context": "".join(context_lines),
                                    "last_modified": datetime.fromtimestamp(os.path.getmtime(file_path)).strftime("%Y-%m-%d")
                                }
                                results["matches"].append(match)
                                results["total_occurrences"] += 1
                except Exception as e:
                    continue  # Skip files that can't be read
        
        return results
    except Exception as e:
        results["error"] = str(e)
        return results

# ThreatFox API Query
def query_threatfox(ioc_type: str, ioc_value: str) -> str:
    tf_api_key = os.getenv("TF_API_KEY")
    if not tf_api_key:
        return "ThreatFox API Key not found in environment variables."

    url = "https://threatfox-api.abuse.ch/api/v1/"
    headers = {"Auth-key": tf_api_key}
    data = {"query": "search_ioc", "search_term": ioc_value, "exact_match": False}

    try:
        response = requests.post(url, headers=headers, json=data, timeout=10)
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
                return f"No entries found in ThreatFox for this IoC."
        else:
            return f"Query not successful or no data found."
    except Exception as e:
        return f"Error querying ThreatFox: {e}"

# VirusTotal API Query
def query_virustotal(ioc_type: str, ioc_value: str) -> str:
    vt_api_key = os.getenv("VT_API_KEY")
    if not vt_api_key:
        return "VirusTotal API Key not found in environment variables."

    if ioc_type == "ip":
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ioc_value}"
    elif ioc_type == "domain":
        url = f"https://www.virustotal.com/api/v3/domains/{ioc_value}"
    elif ioc_type == "hash":
        url = f"https://www.virustotal.com/api/v3/files/{ioc_value}"
    else:
        return "Unsupported IoC type for VirusTotal."

    headers = {"accept": "application/json", "x-apikey": vt_api_key}
    try:
        response = requests.get(url, headers=headers, timeout=10)
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
    except Exception as e:
        return f"Error querying VirusTotal: {e}"

# IoC Classifier
def classifier(ioc_list: list) -> str:
    result_log = []
    for ioc in ioc_list:
        ioc = ioc.strip()
        if not ioc:
            continue
        result_log.append(f"=== Analyzing: {ioc} ===")

        # Hash Detection
        if re.fullmatch(r"[a-fA-F0-9]{64}", ioc):
            result_log.append("Detected file hash (SHA256).")
            result_log.append("--- VirusTotal ---")
            result_log.append(query_virustotal("hash", ioc))
            result_log.append("--- ThreatFox ---")
            result_log.append(query_threatfox("hash", ioc))
            continue

        if re.fullmatch(r"[a-fA-F0-9]{40}", ioc):
            result_log.append("Detected file hash (SHA1).")
            result_log.append("--- VirusTotal ---")
            result_log.append(query_virustotal("hash", ioc))
            result_log.append("--- ThreatFox ---")
            result_log.append(query_threatfox("hash", ioc))
            continue

        if re.fullmatch(r"[a-fA-F0-9]{32}", ioc):
            result_log.append("Detected file hash (MD5).")
            result_log.append("--- VirusTotal ---")
            result_log.append(query_virustotal("hash", ioc))
            result_log.append("--- ThreatFox ---")
            result_log.append(query_threatfox("hash", ioc))
            continue

        # IPv4 Detection
        ipv4_regex = (
            r"^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\."
            r"(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\."
            r"(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\."
            r"(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$"
        )
        if re.fullmatch(ipv4_regex, ioc):
            result_log.append("Detected IPv4 address.")
            result_log.append("--- VirusTotal ---")
            result_log.append(query_virustotal("ip", ioc))
            result_log.append("--- ThreatFox ---")
            result_log.append(query_threatfox("ip", ioc))
            continue

        # IPv6 Detection
        try:
            if ipaddress.ip_address(ioc).version == 6:
                result_log.append("Detected IPv6 address.")
                result_log.append("--- VirusTotal ---")
                result_log.append(query_virustotal("ip", ioc))
                result_log.append("--- ThreatFox ---")
                result_log.append(query_threatfox("ip", ioc))
                continue
        except Exception:
            pass

        # Domain Detection
        domain_regex = (
            r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
            r"(\.[A-Za-z0-9-]{1,63})*"
            r"\.[A-Za-z]{2,}$"
        )
        if re.fullmatch(domain_regex, ioc):
            result_log.append("Detected domain.")
            result_log.append("--- VirusTotal ---")
            result_log.append(query_virustotal("domain", ioc))
            result_log.append("--- ThreatFox ---")
            result_log.append(query_threatfox("domain", ioc))
            continue

        # Fallback
        result_log.append("Unsupported or unrecognized IoC type or format.")
    return "\n\n".join(result_log)

# File Reading Utility
def read_txt_file(uploaded_file):
    try:
        content = uploaded_file.read()
        encoding = chardet.detect(content)['encoding'] or 'utf-8'
        text = content.decode(encoding, errors='ignore')
        ioc_lines = [line.strip() for line in text.splitlines() if line.strip()]
        ioc_list = []
        for line in ioc_lines:
            parts = [ioc.strip() for ioc in line.split(",") if ioc.strip()]
            ioc_list.extend(parts)
        return ioc_list
    except Exception as e:
        st.error(f"Error reading TXT file: {e}")
        return []

# Filter out private/local IOCs
def filter_private_iocs(ioc_list: List[str]) -> Tuple[List[str], List[str]]:
    """Filter out private/local IOCs and return (valid_iocs, private_iocs)"""
    valid_iocs = []
    private_iocs = []
    
    for ioc in ioc_list:
        if is_private_ioc(ioc):
            private_iocs.append(ioc)
        else:
            valid_iocs.append(ioc)
            
    return valid_iocs, private_iocs

# Lottie Animation
report_anim = load_lottieurl("https://lottie.host/e336dcda-a031-494f-af2e-b8e514da4d00/8CdcraVJe0.json")

# Sidebar Navigation
with st.sidebar:
    if report_anim:
        st_lottie(report_anim, height=105, key="sidebar_anim")
    st.title("Threat Navigation Panel")
    st.radio("Navigate to", pages, index=pages.index(st.session_state.selected_page), key="selected_page")

def run_ioc_analysis(ioc: str) -> Dict:
    """Run full analysis pipeline for a single IOC"""
    timestamp = datetime.now().isoformat()
    ioc_type = detect_ioc_type(ioc)
    dataset_results = search_local_datasets(ioc)
    tool_results = classifier([ioc])
    
    # Format dataset results for knowledge source
    dataset_knowledge = "===== Local Dataset Findings =====\n"
    if dataset_results.get('matches'):
        dataset_knowledge += f"Total Occurrences: {dataset_results['total_occurrences']}\n"
        dataset_knowledge += f"Datasets Searched: {dataset_results['datasets_searched']}\n\n"
        for idx, match in enumerate(dataset_results['matches']):
            dataset_knowledge += (
                f"--- Match {idx+1} ---\n"
                f"Dataset: {match['dataset_name']}\n"
                f"File: {match['file_name']}\n"
                f"Path: {match['file_path']}\n"
                f"Line Number: {match['line_number']}\n"
                f"Last Modified: {match['last_modified']}\n"
                f"Context:\n{match['context']}\n\n"
            )
    else:
        dataset_knowledge += (
            f"No matches found in {dataset_results.get('datasets_searched', 0)} "
            f"local dataset files\n"
        )
        if dataset_results.get("error"):
            dataset_knowledge += f"Error: {dataset_results['error']}\n"
    
    # Combine tool results and dataset knowledge into a single string
    combined_knowledge = f"""
    ===== External Tool Results =====
    {tool_results}
    
    {dataset_knowledge}
    """
    knowledge_source = StringKnowledgeSource(content=combined_knowledge)
    
    # Configure LLM
    llm = LLM(
        model="ollama/llama3.2:latest",
        temperature=0.4,
        base_url="http://localhost:11434",
        max_tokens=16000
    )
    
    # Define agents with both knowledge sources
    # Researcher Agent
    researcher = Agent(
        role="Threat Intelligence Researcher",
        goal=f"""
        Conduct comprehensive research on the provided suspected IoCs.
        For each provided suspected IoC:
        - Determine exact type and category
        - Extract all technical attributes
        - Identify related threats and campaigns
        - Gather historical sightings
        - Analyze behavior patterns
        - Document all findings with sources
        - Incorporate both tool results and local dataset findings into analysis
        """,
        backstory="Specializes in deep technical analysis of IOCs",
        verbose=True,
        knowledge_sources=[knowledge_source],  # Single combined source
        llm=llm
    )
    
    fact_checker = Agent(
        role="Threat Intelligence Fact-Checker",
        goal=f"""
        Execute layered verification of all extracted threat intelligence.
        For each key field (malware family, tags, threat type, detection engines, confidence, timestamps): 
        - Log the value provided by the researcher
        - Log the value(s) found in both tool outputs and dataset findings
        - Explicitly state if the values match (Y/N), and if not, flag the contradiction
        - If a value is missing, note it
        - Assemble a clean, verified field set for analysis
        """,
        backstory="An experienced cyber threat validation expert",
        verbose=True,
        llm=llm,
    )
    
    analyzer = Agent(
        role="Threat Intelligence Analyzer",
        goal=f"""
        Analyze the provided suspected IoCs.
        For each provided suspected IoC:
        - Correlate all verified intelligence from both tools and datasets
        - Incorporate threat confidence scoring with justification
        - Include MITRE ATT&CK technique and tactic mappings
        - Provide defensive insights
        - Highlight patterns across both external tools and local datasets
        - Produce Threat Confidence score 0-100 based on your analysis
        """,
        backstory="Expert in threat intelligence analysis",
        verbose=True,
        llm=llm
    )
    
    reporter = Agent(
        role="Threat Intelligence Reporter",
        goal=f"""
        Generate comprehensive professional report on provided suspected IoCs.
        - Start with IOC classification
        - Include detailed findings from both tools and local datasets
        - Provide threat assessment
        - Include mitigation strategies
        - Format professionally with clear sections
        """,
        backstory="Technical writer specializing in threat reports",
        verbose=True,
        llm=llm
    )
    
    # Define tasks (remain unchanged)
    research_task = Task(
        description=f"Research technical details of the IOC: {ioc}",
        expected_output="Detailed technical analysis of the IOC",
        agent=researcher
    )

    factcheck_task = Task(
        description=f"Fact-check the extracted intelligence for: {ioc}",
        expected_output="""
                        Fully verified set of threat intelligence ready for analytical correlation, with explicit field-by-field source verification log.
                        """,
        agent=fact_checker,
        context=[research_task]
    )
    
    analyze_task = Task(
        description=f"Analyze findings for: {ioc}",
        expected_output="""
                        Comprehensive local dataset correlation report including:
                        - List of all dataset files containing the IOC
                        - Exact line numbers of matches
                        - Contextual information around each match
                        - File modification dates
                        - Any patterns across datasets
                        """,
        agent=analyzer,
        context=[research_task]
    )
    
    report_task = Task(
        description=f"Generate final threat report for: {ioc}",
        expected_output="""
                        Professional threat intelligence report containing:
                        - Clear IOC classification
                        - Prominent display of local dataset matches
                        - Technical analysis
                        - Threat assessment
                        - Mitigation recommendations
                        - Properly formatted with sections
                        """,
        agent=reporter,
        context=[research_task, analyze_task]
    )
    
    # Create and run crew
    crew = Crew(
        agents=[researcher, fact_checker, analyzer, reporter],
        tasks=[research_task, factcheck_task, analyze_task, report_task],
        process=Process.sequential,
        verbose=True
    )
    
    result = crew.kickoff(inputs={"ioc_input": ioc})
    
    return {
        "report": str(result),
        "dataset_results": dataset_results,
        "ioc_type": ioc_type,
        "tool_results": tool_results,
        "combined_knowledge": combined_knowledge,  # Store for reference
        "timestamp": timestamp
    }

# Generate ZIP file for batch download
def generate_batch_zip(individual_reports: Dict) -> bytes:
    zip_buffer = BytesIO()
    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zip_file:
        for ioc, report_data in individual_reports.items():
            safe_ioc = re.sub(r'[^a-zA-Z0-9]', '_', ioc)
            filename = f"threat_report_{safe_ioc}.txt"
            content = (
                f"=== IOC Analysis Report ===\n"
                f"IOC: {ioc}\n"
                f"Type: {report_data['ioc_type'][0]}\n"
                f"Category: {report_data['ioc_type'][1]}\n"
                f"Generated: {report_data['timestamp']}\n\n"
                f"===== Report =====\n"
                f"{report_data['report']}\n\n"
                f"===== Dataset Results =====\n"
                f"Total Matches: {len(report_data['dataset_results'].get('matches', []))}\n"
                f"Datasets Searched: {report_data['dataset_results'].get('datasets_searched', 0)}\n"
            )
            zip_file.writestr(filename, content)
    zip_buffer.seek(0)
    return zip_buffer.getvalue()

# Main Single IOC Analysis Page
if st.session_state.selected_page == "Single IOC Analysis":
    st.title("Single IOC Threat Intelligence Analyzer")
    st.markdown("Analyze a single indicator of Compromise (IOC)")
    
    single_ioc = st.text_input("Enter a single IOC (IP, Domain, Hash):", placeholder="8.8.8.8 or example.com")
    
    if st.button("Analyze IOC"):
        if single_ioc:
            # Check for private/local IOC
            if is_private_ioc(single_ioc):
                st.warning(f"⚠️ Private/localhost IOC detected: {single_ioc}. These are not analyzed.")
                st.info("Please provide a public IOC for analysis.")
            else:
                with st.spinner(f"Analyzing {single_ioc}..."):
                    # Run analysis pipeline
                    report_data = run_ioc_analysis(single_ioc)
                    
                    # Store in session state
                    st.session_state.individual_reports[single_ioc] = report_data
                    st.session_state.selected_ioc_report = single_ioc
                    
                st.success("✅ Analysis complete! View the report under the 'Report' tab.")
                st.session_state.nav_to_page = "Report"
                st.rerun()
        else:
            st.warning("Please enter an IOC to analyze")

# Multiple IOC Analysis Page
elif st.session_state.selected_page == "Multiple IOC Analysis":
    st.title("Multiple IOC Threat Intelligence Analyzer")
    st.markdown("Analyze multiple IOCs or upload a batch file")
    
    tab1, tab2 = st.tabs(["Multiple IOCs", "Batch Upload"])
    
    with tab1:
        ioc_text = st.text_area("Enter multiple IOCs (one per line or comma separated):", height=150)
        analyze_button = st.button("Analyze Multiple IOCs")
        
        if analyze_button and ioc_text:
            raw_ioc_list = [ioc.strip() for line in ioc_text.splitlines() for ioc in line.split(",") if ioc.strip()]
            
            if not raw_ioc_list:
                st.warning("Please enter at least one valid IOC")
                st.stop()
                
            # Filter out private IOCs
            valid_iocs, private_iocs = filter_private_iocs(raw_ioc_list)
            st.session_state.private_iocs = private_iocs
            
            if private_iocs:
                st.warning(f"⚠️ Skipped {len(private_iocs)} private/localhost IOCs:")
                st.write(", ".join(private_iocs))
                st.info("Private/localhost IOCs are not analyzed.")
            
            if not valid_iocs:
                st.error("No valid public IOCs to analyze.")
                st.stop()
                
            st.session_state.ioc_list = valid_iocs
            st.session_state.individual_reports = {}
            
            progress_bar = st.progress(0)
            status_text = st.empty()
            
            for idx, ioc in enumerate(valid_iocs):
                status_text.text(f"Analyzing {idx+1}/{len(valid_iocs)}: {ioc}")
                progress_bar.progress((idx + 1) / len(valid_iocs))
                
                try:
                    report_data = run_ioc_analysis(ioc)
                    st.session_state.individual_reports[ioc] = report_data
                except Exception as e:
                    st.error(f"Error analyzing {ioc}: {str(e)}")
            
            st.session_state.selected_ioc_report = valid_iocs[0]
            st.success("✅ Batch analysis complete! View reports under the 'Report' tab.")
            st.session_state.nav_to_page = "Report"
            st.rerun()
    
    with tab2:
        uploaded_file = st.file_uploader("Upload a batch file with IOCs", type=["txt"])
        st.caption("File should contain one IOC per line or comma-separated values")
        
        if st.button("Start Batch Analysis") and uploaded_file:
            raw_ioc_list = read_txt_file(uploaded_file)
            
            if not raw_ioc_list:
                st.warning("No valid IOCs found in the uploaded file")
                st.stop()
                
            # Filter out private IOCs
            valid_iocs, private_iocs = filter_private_iocs(raw_ioc_list)
            st.session_state.private_iocs = private_iocs
            
            if private_iocs:
                st.warning(f"⚠️ Skipped {len(private_iocs)} private/localhost IOCs:")
                st.write(", ".join(private_iocs))
                st.info("Private/localhost IOCs are not analyzed.")
            
            if not valid_iocs:
                st.error("No valid public IOCs to analyze.")
                st.stop()
                
            st.session_state.ioc_list = valid_iocs
            st.session_state.individual_reports = {}
            
            progress_bar = st.progress(0)
            status_text = st.empty()
            
            for idx, ioc in enumerate(valid_iocs):
                status_text.text(f"Analyzing {idx+1}/{len(valid_iocs)}: {ioc}")
                progress_bar.progress((idx + 1) / len(valid_iocs))
                
                try:
                    report_data = run_ioc_analysis(ioc)
                    st.session_state.individual_reports[ioc] = report_data
                except Exception as e:
                    st.error(f"Error analyzing {ioc}: {str(e)}")
            
            st.session_state.selected_ioc_report = valid_iocs[0]
            st.success("✅ Batch analysis complete! View reports under the 'Report' tab.")
            st.session_state.nav_to_page = "Report"
            st.rerun()

# Report Page
elif st.session_state.selected_page == "Report":
    if report_anim:
        st_lottie(report_anim, height=150, key="report_anim")
    
    if not st.session_state.individual_reports:
        st.warning("No reports available. Please analyze at least one IOC.")
        if st.button("🔍 Go to Analysis Page"):
            st.session_state.nav_to_page = "Single IOC Analysis"
            st.rerun()
    else:
        st.header("📄 Threat Intelligence Reports")
        
        # Show warning about skipped private IOCs if any
        if st.session_state.private_iocs:
            with st.expander("⚠️ Skipped Private IOCs", expanded=True):
                st.warning(f"{len(st.session_state.private_iocs)} private/localhost IOCs were skipped:")
                st.write(", ".join(st.session_state.private_iocs))
                st.info("Private and localhost IOCs are not analyzed as they typically represent internal infrastructure.")
        
        # Generate batch ZIP if needed
        if len(st.session_state.individual_reports) > 1:
            if not st.session_state.batch_zip:
                st.session_state.batch_zip = generate_batch_zip(st.session_state.individual_reports)
            
            st.download_button(
                label="💾 Download All Reports (ZIP)",
                data=st.session_state.batch_zip,
                file_name="threat_intel_reports.zip",
                mime="application/zip",
            )
            st.caption(f"Contains {len(st.session_state.individual_reports)} individual reports")
        
        # IOC selection dropdown
        ioc_options = list(st.session_state.individual_reports.keys())
        
        # Use session state to track selected IOC
        if "selected_ioc_report" not in st.session_state:
            st.session_state.selected_ioc_report = ioc_options[0]
        
        # Create the selectbox and update session state on change
        selected_ioc = st.selectbox(
            "Select an IOC to view detailed report:",
            ioc_options,
            index=ioc_options.index(st.session_state.selected_ioc_report),
            key="ioc_selector"
        )
        
        # Update session state when selection changes
        if selected_ioc != st.session_state.selected_ioc_report:
            st.session_state.selected_ioc_report = selected_ioc
            st.rerun()
        
        # Display selected report
        if st.session_state.selected_ioc_report in st.session_state.individual_reports:
            report_data = st.session_state.individual_reports[st.session_state.selected_ioc_report]
            ioc_type, ioc_category = report_data["ioc_type"]
            timestamp = datetime.fromisoformat(report_data["timestamp"]).strftime("%Y-%m-%d %H:%M:%S")
            
            st.markdown(f"""
            ### Analysis Report for: `{st.session_state.selected_ioc_report}`
            **Type**: {ioc_type}  
            **Category**: {ioc_category}  
            **Report Generated**: {timestamp}
            """)
            
            # Dataset Findings Section
            with st.expander("🔍 Local Dataset Matches", expanded=True):
                if report_data["dataset_results"].get("matches"):
                    st.success(f"✅ IOC found in {len(report_data['dataset_results']['matches'])} locations across local datasets")
                    
                    for match in report_data["dataset_results"]["matches"]:
                        with st.container():
                            st.markdown(f"""
                            **Dataset File**: `{match['file_name']}`  
                            **Path**: {match['file_path']}  
                            **Line Number**: {match['line_number']}  
                            **Last Modified**: {match['last_modified']}
                            """)
                            with st.expander("View Match Context"):
                                st.code(match['context'])
                else:
                    st.warning(f"No matches found in {report_data['dataset_results'].get('datasets_searched', 0)} local dataset files")
                    if report_data["dataset_results"].get("error"):
                        st.error(f"Error searching datasets: {report_data['dataset_results']['error']}")
            
            # Technical Analysis Section
            with st.expander("🛠️ Technical Analysis", expanded=True):
                st.markdown(report_data["report"])
            
            # Download button for individual report
            report_content = (
                f"=== IOC Analysis Report ===\n"
                f"IOC: {st.session_state.selected_ioc_report}\n"
                f"Type: {ioc_type}\n"
                f"Category: {ioc_category}\n"
                f"Generated: {timestamp}\n\n"
                f"===== Report =====\n"
                f"{report_data['report']}\n\n"
                f"===== Dataset Results =====\n"
                f"Total Matches: {len(report_data['dataset_results'].get('matches', []))}\n"
                f"Datasets Searched: {report_data['dataset_results'].get('datasets_searched', 0)}\n"
            )
            
            st.download_button(
                label=f"💾 Download Report for {st.session_state.selected_ioc_report}",
                data=report_content,
                file_name=f"threat_report_{re.sub(r'[^a-zA-Z0-9]', '_', st.session_state.selected_ioc_report)}.txt",
                mime="text/plain"
            )
        
        # Button to go back to Input page
        if st.button("🔄 Analyze Another IoC"):
            st.session_state.nav_to_page = "Single IOC Analysis"
            st.rerun()