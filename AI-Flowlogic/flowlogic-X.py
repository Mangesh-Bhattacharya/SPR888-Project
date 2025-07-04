import io
import os
import re
import random
import time
import chardet
import pandas as pd
import requests
import streamlit as st
import zipfile
import urllib.robotparser
import idna, ipaddress
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from dotenv import load_dotenv
from datetime import datetime
from streamlit_lottie import st_lottie
from fake_useragent import UserAgent
from crewai import Agent, Task, Crew, Process, LLM
from crewai.knowledge.source.string_knowledge_source import StringKnowledgeSource

# Try import fake_useragent. Fallback if not installed.
try:
    def get_random_user_agent():
        return UserAgent().random
except ImportError:
    def get_random_user_agent():
        agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_0) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.2 Safari/605.1.15",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
        ]
        return random.choice(agents)

# CrewAI (and LLMs)
# ============ Load env variables ============ #
load_dotenv()

# ============ Stealthy Web Scraper ============ #
class StealthyWebScraper:
    DEFAULT_TIMEOUT = 12
    MAX_RETRIES = 3

    def __init__(self, proxies=None):
        self.proxies = proxies

    def is_allowed(self, url):
        parsed = urlparse(url)
        rp = urllib.robotparser.RobotFileParser()
        rp.set_url(f"{parsed.scheme}://{parsed.netloc}/robots.txt")
        try:
            rp.read()
            return rp.can_fetch("*", url)
        except Exception:
            return True

    def get(self, url, use_stealth=True, check_robots=True):
        if check_robots and not self.is_allowed(url):
            raise Exception(f"Blocked by robots.txt: {url}")
        tries = 0
        while tries < self.MAX_RETRIES:
            headers = {
                "User-Agent": get_random_user_agent() if use_stealth else "Mozilla/5.0",
                "Accept-Language": "en-US,en;q=0.9",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
                "Connection": "close",
                "Referer": "https://www.google.com/"
            }
            try:
                resp = requests.get(url, headers=headers, timeout=self.DEFAULT_TIMEOUT, proxies=self.proxies)
                if resp.status_code == 200:
                    if use_stealth:
                        time.sleep(random.uniform(1.3, 3.9))
                    return resp.text
                elif resp.status_code in [403, 429]:
                    time.sleep(random.uniform(2, 8))
            except Exception:
                time.sleep(random.uniform(1, 2))
            tries += 1
        raise Exception(f"Failed to fetch {url} after {self.MAX_RETRIES} attempts.")

    def soup(self, url, **kwargs):
        html = self.get(url, **kwargs)
        return BeautifulSoup(html, "html.parser")

# ============ Navigation State Management ============ #
pages = ["Input", "Report"]
if "selected_page" not in st.session_state:
    st.session_state.selected_page = pages[0]
if "nav_to_page" not in st.session_state:
    st.session_state["nav_to_page"] = None

if st.session_state.get("nav_to_page") in pages:
    st.session_state.selected_page = st.session_state.nav_to_page
    st.session_state.nav_to_page = None
    st.rerun()

# ============ Page Config & CSS ============ #
st.set_page_config(page_title="Threat Intelligence Report Generator", layout="centered")
st.markdown("""
<style>
/* ---- Main Card Layouts & Backgrounds ---- */
.stExpander, .stTabs [data-baseweb="tab-panel"] {
    max-width: 1400px !important;
    width: 100% !important;
    margin-left: auto !important;
    margin-right: auto !important;
    background: #191d23 !important;
    border-radius: 16px !important;
    box-shadow: 0 4px 24px 0 rgba(26,32,52,0.13), 0 1.5px 3px #0001;
    padding: 2.2rem 2.5rem 1.7rem 2.5rem !important;
    border: 1.5px solid #24283822;
    margin-bottom: 1.25rem !important;    /* <--- This ensures clear space between cards */
}

.stExpanderHeader {
    font-size: 1.18rem;
    color: #22a1e2 !important;
    font-weight: 700 !important;
    letter-spacing: 0.01em;
}

/* ---- Associated Campaigns: Soft Card, No Border ---- */
.associated-campaigns-box {
    background: #f7fafd !important;
    border-radius: 14px !important;
    border: none !important;
    box-shadow: none !important;
    padding: 1.7rem 1.8rem 1.1rem 1.8rem !important;
    margin-bottom: 1.2em !important;
    margin-top: 0.2em;
    min-width: 100%;
}
.associated-campaigns-label {
    color: #f2a540;
    font-weight: 700;
    font-size: 1.14rem;
    margin-bottom: 0.7em;
    display: block;
}

/* ---- Headings, Taglines, Accents ---- */
.headline {
    font-size: 2.6rem;
    font-weight: 800;
    color: #f7fafc;
    margin-bottom: 0.15em;
    letter-spacing: -1px;
}
.section-title, .stMarkdown strong, .stMarkdown b {
    color: #f4b945 !important;
    font-weight: 700 !important;
}
.stMarkdown h1, .stMarkdown h2, .stMarkdown h3 {
    color: #22a1e2 !important;
    font-weight: 700 !important;
    margin-bottom: 0.7em !important;
    margin-top: 1.1em !important;
}
.tagline {
    font-size: 1.18rem;
    color: #b2b8c6;
    margin-bottom: 2.1em;
    font-weight: 500;
}
.accent { color: #184fa1 !important; }

/* ---- Buttons ---- */
.stButton>button {
    background: linear-gradient(90deg, #3065B5 60%, #67B3FE 100%);
    color: white;
    font-weight: bold;
    border-radius: 8px;
    border: none;
    height: 3em;
    font-size: 1.05rem;
    box-shadow: 0 2px 8px 0 #0001;
}
.stDownloadButton { min-width: 230px; }

/* ---- Sidebar ---- */
[data-testid="stSidebar"] h1, [data-testid="stSidebar"] h2 { color: #184fa1 !important; }

/* ---- Metric Cards ---- */
.stMetric { background: #f4f8ff !important; border-radius:12px !important;}
div[data-testid="stMetric"] {
    background: linear-gradient(90deg, #253350 40%, #275ba8 100%) !important;
    color: #fff !important;
    border-radius: 18px !important;
    box-shadow: 0 2px 12px 0 rgba(20,45,80,0.17) !important;
    min-height: 90px;
    padding: 1.3rem 1.1rem 1.1rem 1.1rem;
}
div[data-testid="stMetric"] label,
div[data-testid="stMetric"] span,
div[data-testid="stMetric"] > div { color: #fff !important; font-weight: 600 !important; }
div[data-testid="stMetric"] .stMetricLabel { font-size: 1.05rem !important; opacity: 0.96 !important; letter-spacing:0.5px;}
div[data-testid="stMetric"] .stMetricValue {
    font-size: 2.23rem !important; font-weight: 900 !important; margin-top: 0.08rem !important;
    letter-spacing:1px !important; color: #ed2536 !important;
    text-shadow: 0 3px 13px #65060622, 0 1px 0 #fff2;
}

/* ---- Markdown/Text/DF styling ---- */
.stMarkdown, .stText, .stDataFrame {
    word-break: break-word !important;
    white-space: pre-line !important;
    color: #e7ecf3 !important;
    font-size: 1.13rem !important;
    line-height: 1.7 !important;
    background: none !important;
    border: none !important;
}

/* ---- Lists: Style and Spacing ---- */
.stMarkdown ul, .stMarkdown ol {
    padding-left: 2rem !important;
    margin-bottom: 0.7em !important;
}
.stMarkdown ul li, .stMarkdown ol li {
    margin-bottom: 0.32em !important;
    padding-left: 2px;
    font-size: 1.08rem;
    color: #e6eef6;
}
.stMarkdown ol li::marker {
    font-weight: bold;
    color: #47bdb8;
}
.stMarkdown ul li::before {
    content: '';
    background-color: #47bdb8;
    border-radius: 50%;
    display: inline-block;
    width: 7px;
    height: 7px;
    margin-right: 0.75em;
    position: relative;
    top: 0.10em;
}

/* ---- Text areas and Inputs (dark style) ---- */
textarea, .stTextArea, .stTextInput {
    background: #181b20 !important;
    border: 1px solid #364d69 !important;
    border-radius: 8px !important;
    color: #e6eef6 !important;
    font-size: 1.03rem;
    padding: 0.7em 1em !important;
    margin-top: 0.5em;
}
.stTextArea textarea {
    scrollbar-width: thin;
    background: #181b20 !important;
    color: #e6eef6 !important;
}

/* ---- Responsive ---- */
@media (max-width: 900px) {
    .stExpander, .stTabs [data-baseweb="tab-panel"], .exec-summary-card {
        max-width: 98vw !important;
        padding: 1.1rem !important;
    }
    .associated-campaigns-box {
        padding: 1.1rem 0.7rem 1rem 1.0rem !important;
    }
}
@media (max-width: 600px) {
    .maincard, .stExpander, .stTabs [data-baseweb="tab-panel"], .exec-summary-card {
        padding: 0.6rem !important;
        font-size: 1.02rem !important;
    }
    .stMarkdown {
        font-size: 1.01rem !important;
    }
}

/* ---- Other ---- */
a { word-break: break-all !important; white-space: pre-line !important; }

</style>
""", unsafe_allow_html=True)


# ============ Session State Defaults ============ #
for key, val in {
    "report_text": None,
    "ioc_input": None,
    "report_date": None,
    "batch_zip": None,
    "batch_names": [],
}.items():
    if key not in st.session_state:
        st.session_state[key] = val

# ============ Formatting Helpers ============ #
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
        markdown = "\n".join([f"{idx+1}.{line.lstrip('1234567890). ')}" for idx, line in enumerate(lines)])
        return markdown
    return ""

def format_related_indicators(text):
    items = [line.strip() for line in text.splitlines() if line.strip()]
    clean_items = []
    for line in items:
        line = re.sub(r"^\s*(\d+[\.\)]\s*)+", "", line)
        clean_items.append(line)
    return "\n".join([f"{idx+1}.{item}" for idx, item in enumerate(clean_items)])

def extract_vt_tf_sections(text):
    vt, tf = "", ""
    vt_match = re.search(r"--- VirusTotal ---([\s\S]+?)(?=--- ThreatFox ---|$)", text)
    tf_match = re.search(r"--- ThreatFox ---([\s\S]+)", text)
    if vt_match:
        vt = vt_match.group(1).strip()
    if tf_match:
        tf = tf_match.group(1).strip()
    return {"virustotal": vt, "threatfox": tf}

# ============ Lottie Animation ============ #
def load_lottieurl(url):
    try:
        r = requests.get(url)
        if r.status_code != 200:
            return None
        return r.json()
    except Exception:
        return None

report_anim = load_lottieurl("https://lottie.host/e336dcda-a031-494f-af2e-b8e514da4d00/8CdcraVJe0.json")

# ============ Sidebar Navigation ============ #
with st.sidebar:
    if report_anim:
        st_lottie(report_anim, height=105, key="sidebar_anim")
    st.title("Threat Navigation Panel")
    st.radio("Navigate to", pages, index=pages.index(st.session_state.selected_page), key="selected_page")

# ============ File Reading Utility ============ #
def get_dataframe(uploaded_file):
    filename = uploaded_file.name.lower()
    if filename.endswith('.zip'):
        iocs = set()
        try:
            with zipfile.ZipFile(uploaded_file) as zf:
                for inner in zf.namelist():
                    if not inner.lower().endswith(('.csv','.txt','.xls','.xlsx')):
                        continue
                    with zf.open(inner) as f:
                        sample = f.read(10000)
                        encoding = chardet.detect(sample)['encoding'] or "utf-8"
                        f.seek(0)
                        if inner.lower().endswith(('.xls', '.xlsx')):
                            try:
                                df = pd.read_excel(f, header=None, usecols=[0])
                                for v in df[0].dropna().unique():
                                    iocs.add(str(v).strip())
                            except Exception:
                                continue
                        else:
                            try:
                                lines = sample.decode(encoding, errors="ignore").splitlines()
                                for l in lines:
                                    val = l.strip()
                                    if val: iocs.add(val)
                            except Exception:
                                continue
            if iocs:
                return pd.DataFrame(list(iocs))
            else:
                return None
        except Exception as e:
            st.error(f"ZIP extraction failed: {e}")
            return None
    elif filename.endswith(('.xls', '.xlsx')):
        try:
            df = pd.read_excel(uploaded_file, header=None, usecols=[0])
            return df
        except Exception as e:
            st.error(f"Could not read Excel file: {e}")
            return None
    else:
        uploaded_file.seek(0)
        raw_bytes = uploaded_file.read(10000)
        uploaded_file.seek(0)
        encoding = chardet.detect(raw_bytes)['encoding'] or "utf-8"
        try:
            df = pd.read_csv(uploaded_file, header=None, encoding=encoding)
            return df
        except Exception:
            uploaded_file.seek(0)
            try:
                df = pd.read_csv(uploaded_file, header=None, encoding="utf-8-sig", usecols=[0])
                return df
            except Exception:
                uploaded_file.seek(0)
                try:
                    df = pd.read_csv(uploaded_file, header=None, encoding="latin1", usecols=[0])
                    return df
                except Exception as e:
                    st.error(f"Could not read file as CSV/text: {e}")
                    return None

# ============ Main Input Page ============ #
if st.session_state.selected_page == "Input":
    st.title("🔍 Threat Intelligence Report Generator")
    st.markdown("""
        Research and analyze suspicious indicators such as IP addresses, domains, file hashes 
        to generate a threat intelligence report.
    """)
    st.header("Enter suspected Indicator of Compromise (IoC)")
    uploaded_file = st.file_uploader(
        "Upload a file with IoCs (CSV, TXT, XLS, XLSX, or ZIP with these inside)", 
        type=["csv", "txt", "xls", "xlsx", "zip"]
    )
    st.markdown(
        "Upload a file with the IoCs (no header required, 1 per line/cell). "
        "Alternatively, enter a single IoC below."
    )
    ioc_input = st.text_input("Or enter a single IoC (IP, domain, or hash):")
    start_button = st.button("🧠 Start Threat Analysis")

    def run_threat_analysis(ioc_input):
        llm = LLM(
            model="ollama/llama3.2:latest",
            temperature=0.2,
            base_url="http://localhost:11434",
        )
        # ============ VirusTotal Queries ============ #
        def query_virustotal(ioc_type: str, ioc_value: str) -> str:
            vt_api_key = os.getenv("VT_API_KEY")
            if not vt_api_key:
                return "VirusTotal API Key not found."
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
        def query_threatfox(ioc_type: str, ioc_value: str) -> str:
            tf_api_key = os.getenv("TF_API_KEY")
            if not tf_api_key:
                return "ThreatFox API Key not found."
            url = "https://threatfox-api.abuse.ch/api/v1/"
            headers = {"API-KEY": tf_api_key}
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

        def classifier(ioc: str) -> str:
            ioc = ioc.strip()
            result_log = []
            # ---------- Hashes ---------------#
            if re.fullmatch(r"[a-fA-F0-9]{64}", ioc):
                result_log.append("Detected file hash (SHA256).")
                result_log.append("--- VirusTotal ---")
                result_log.append(query_virustotal("hash", ioc))
                result_log.append("--- ThreatFox ---")
                result_log.append(query_threatfox("hash", ioc))
                return "\n".join(result_log)
            if re.fullmatch(r"[a-fA-F0-9]{40}", ioc):
                result_log.append("Detected file hash (SHA1).")
                result_log.append("--- VirusTotal ---")
                result_log.append(query_virustotal("hash", ioc))
                result_log.append("--- ThreatFox ---")
                result_log.append(query_threatfox("hash", ioc))
                return "\n".join(result_log)
            if re.fullmatch(r"[a-fA-F0-9]{32}", ioc):
                result_log.append("Detected file hash (MD5).")
                result_log.append("--- VirusTotal ---")
                result_log.append(query_virustotal("hash", ioc))
                result_log.append("--- ThreatFox ---")
                result_log.append(query_threatfox("hash", ioc))
                return "\n".join(result_log)
            # ---------- IPv4 ---------- #
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
                return "\n".join(result_log)
            # ---------- IPv6 ---------- #
            try:
                if ipaddress.ip_address(ioc).version == 6:
                    result_log.append("Detected IPv6 address.")
                    result_log.append("--- VirusTotal ---")
                    result_log.append(query_virustotal("ip", ioc))
                    result_log.append("--- ThreatFox ---")
                    result_log.append(query_threatfox("ip", ioc))
                    return "\n".join(result_log)
            except Exception:
                pass
            # ---------- Domain ---------- #
            domain_regex = (
                r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
                r"(\.[A-Za-z0-9-]{1,63})*"
                r"\.[A-Za-z]{2,}$"
            )
            if re.fullmatch(domain_regex, ioc):
                try:
                    puny = idna.encode(ioc).decode("ascii")
                    result_log.append(f"Detected domain (IDN supported): {puny}")
                except Exception:
                    result_log.append("Detected domain.")
                result_log.append("--- VirusTotal ---")
                result_log.append(query_virustotal("domain", ioc))
                result_log.append("--- ThreatFox ---")
                result_log.append(query_threatfox("domain", ioc))
                return "\n".join(result_log)
            # ---------- Fallback ---------- #
            result_log.append("Unsupported or unrecognized IoC type or format.")
            return "\n".join(result_log)

        tool_results = classifier(ioc_input)
        tool_output = StringKnowledgeSource(content=tool_results if tool_results else "No IoC results found.")
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
        template = StringKnowledgeSource(content=report_template.strip())
        search_output = StringKnowledgeSource(content="No external search results available.")
        researcher = Agent(
            role="Threat Intelligence Researcher",
            goal=(
                "Extract all necessary threat intelligence to populate every section of the final report, "
                "including IoC metadata, detection rates, behavior, and context. Ensure every detail needed "
                "for the following sections is collected: Input Summary, Threat Confidence, Key Findings, "
                "Quick Assessment, Core Attributes, Reputation Analysis, Network Behaviour, Related Indicators, Campaigns, and Detection Signatures. "
                "Make sure to strip any unrelated to cybersecurity threat information."
                "Make sure to organize information under the following headers in your response:  Input Summary, Threat Confidence,  Key Findings, Quick Assessment,  Suspected IoC Core Attributes,  Reputation Analysis,  Network Behaviour Patterns, Associated Activities, Associated Campaigns,  Related Indicators,  Detection Signatures,  Recommendations,  Network Controls Endpoint Protection, References"
                "Make sure Threat Confidence value is just a number of 0-100 with no other text around it"
                "Make sure if you try to make a list of value under any header, make it a numbered list"
            ),
            backstory="Specializes in structured threat data analysis using internal intelligence reports only.",
            verbose=True,
            knowledge_sources=[search_output, tool_output, template],
            llm=llm,
        )
        fact_checker = Agent(
            role="Threat Intelligence Validator",
            goal=(
                "Execute layered verification of all extracted threat intelligence by conducting web search and verifying the information obtained by the researcher. "
                "For each key field (malware family, tags, threat type, detection engines, confidence, timestamps): "
                "1) Log the value provided by the researcher, "
                "2) Log the value(s) found in web search and tool outputs, "
                "3) Explicitly state if the values match (Y/N), and if not, flag the contradiction and show both values, "
                "4) If a value is missing in the web search/tool, note it. "
                "Then, assemble a clean, verified field set for analysis, using only confirmed or explainable values. "
                "If you make a list, always use \\n 1)\\n 2)\\n 3) format instead of bullets or dashes. "
                "Strictly ensure headers match the template verbatim, with no numbering or extra symbols."
            ),
            backstory="An experienced cyber threat validation expert combining open-source research skills with analytical consistency checking. Uses online intelligence sources to confirm threat signatures, uncover contradictions, and ensure timestamp and reputation accuracy across all report fields.",
            knowledge_sources=[template, tool_output, search_output],
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
                "Conclude with defensive insights to guide detection, prevention, and response strategies."
                "Make sure to organize information under the following headers in your response:  Input Summary, Threat Confidence,  Key Findings,  Quick Assessment,  Suspected IoC Core Attributes,  Reputation Analysis,  Network Behaviour Patterns, Associated Activities, Associated Campaigns,  Related Indicators,  Detection Signatures,  Recommendations,  Network Controls Endpoint Protection, References"
                "Make sure Threat Confidence value is just a number of 0-100 with no other text around it"
                "Make sure if you try to make a list of value under any header, make it a numbered list"
            ),
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
                "Make sure to organize information under the following headers in your response:  Input Summary, Threat Confidence, Key Findings, Quick Assessment,  Suspected IoC Core Attributes, Reputation Analysis, Network Behaviour Patterns, Associated Activities, Associated Campaigns, Related Indicators, Detection Signatures, Recommendations, Network Controls Endpoint Protection, References"
                "Make sure Threat Confidence value is just a number of 0-100 with no other text around it"
                "Make sure if you try to make a list of value under any header, make it a numbered list"
            ),
            backstory="Produces professional-grade threat reports with clear formatting and no deviation from structure represented in the template from the knowledge.",
            verbose=True,
            knowledge_sources=[template],
            llm=llm,
        )
        task_research = Task(
            description=(
                "Extract all threat intelligence details from the knowledge base to support every section of the template. "
                "This includes IoC attributes, malware names, detection rates, first seen timestamps, aliases, threat type, and external links, information obtained from the search."
                "Make sure to organize information under the following headers in your response:  Input Summary, Threat Confidence,  Key Findings,  Quick Assessment,  Suspected IoC Core Attributes,  Reputation Analysis,  Network Behaviour Patterns, Associated Activities, Associated Campaigns,  Related Indicators,  Detection Signatures,  Recommendations,  Network Controls Endpoint Protection, References"
            ),
            expected_output="Comprehensive structured threat data aligned to report sections.",
            agent=researcher
        )
        task_fact_check = Task(
            description=(
                "Fact-check the extracted intelligence using external sources. "
                "For each key field (malware family, tags, threat type, detection engines, confidence, timestamps): "
                "1) Log the value provided by the researcher, "
                "2) Log the value(s) found in web search and tool outputs, "
                "3) State if they match (Y/N), flag contradictions and show both, "
                "4) If a value is missing in the external source, note it. "
                "Then, assemble a clean, verified field set for analysis. "
                "If you make a list, always use \\n 1)\\n 2)\\n 3) format instead of bullets or dashes. "
                "Strictly ensure headers match the template verbatim, with no numbering or extra symbols."
            ),
            expected_output="Fully verified set of threat intelligence ready for analytical correlation, with explicit field-by-field source verification log.",
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
                "Use the strict template provided in your knowledge to write a complete professional threat report."
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
                "If the headers go by 1, 2, 3, make sure to remove the numbering, leaving only headers verbatim to the template"),
            expected_output="Finalized threat report containing exact headers from the template from the knowledge, fully completed and confirmed. Threat confidence header should have only value of 0-100 number and no other text.",
            agent=writer,
            context=[task_analyze]
        )
        crew = Crew(
            agents=[researcher, fact_checker, analyzer, writer],
            tasks=[task_research, task_fact_check, task_analyze, task_write, task_confirm_write],
            process=Process.sequential,
            verbose=True,
            memory=False
        )
        result = crew.kickoff(inputs={"ioc_input": ioc_input})
        return str(result)

    # Example usage of the "stealthy" scraper (optional UI for testing)
    with st.expander("🔍 Web Scraper Test Utility"):
        url_to_scrape = st.text_input("Test scrape URL", "")
        if st.button("Scrape (Stealth)"):
            if url_to_scrape:
                try:
                    scraper = StealthyWebScraper()
                    soup = scraper.soup(url_to_scrape)
                    st.markdown(f"**Title:** {soup.title.text if soup.title else 'No title found'}")
                    snippet = soup.prettify()
                    if not isinstance(snippet, str):
                        if isinstance(snippet, memoryview):
                            snippet = snippet.tobytes()
                        if isinstance(snippet, bytes):
                            snippet = snippet.decode("utf-8", errors="replace")
                        else:
                            snippet = str(snippet)
                    st.code(snippet[:800] + " ...", language="html")
                except Exception as e:
                    st.error(f"Scraping failed: {e}")

    # ============ Start Button Logic ============ #
    if start_button:
        if uploaded_file is not None:
            df = get_dataframe(uploaded_file)
            if df is None:
                st.error("Unable to read uploaded file. Please upload a valid CSV, TXT, XLS, XLSX or ZIP.")
            else:
                ioc_list = pd.Series(df.iloc[:,0].dropna().unique())
                st.info(f"Processing {len(ioc_list)} IoCs in batch. This will take some time.")
                reports = []
                zip_buffer = io.BytesIO()
                with zipfile.ZipFile(zip_buffer, "w") as zip_file:
                    for idx, ioc in enumerate(ioc_list, 1):
                        st.write(f"Processing {idx}/{len(ioc_list)}: {ioc}")
                        report = run_threat_analysis(ioc)
                        file_name = f"report_{str(ioc).replace(':','_').replace('/','_')}.txt"
                        zip_file.writestr(file_name, report)
                        reports.append(file_name)
                zip_buffer.seek(0)
                st.session_state.batch_zip = zip_buffer.read()
                st.session_state.batch_names = reports
                st.session_state.report_text = None
                st.session_state.nav_to_page = "Report"
                st.rerun()
        elif ioc_input:
            st.session_state.ioc_input = ioc_input
            st.session_state.report_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            st.info("Initializing threat intelligence research and analysis using multi-agent system...")
            with st.spinner("Running analysis. This may take a few moments..."):
                st.session_state.report_text = run_threat_analysis(ioc_input)
            st.session_state.nav_to_page = "Report"
            st.rerun()
        else:
            st.warning("Please upload a file or enter a single IoC.")

# ============ Report Page ============ #
elif st.session_state.selected_page == "Report":
    if report_anim:
        st_lottie(report_anim, height=150, key="report_anim")
    if st.session_state.get("batch_zip") and isinstance(st.session_state.batch_zip, bytes):
        st.header("📄 Batch Threat Intelligence Reports")
        st.success("Your batch is ready! Download all threat reports as a ZIP file below.")
        st.download_button(
            label="💾 Download All Reports (ZIP)",
            data=st.session_state.batch_zip,
            file_name="threat_intel_reports.zip",
            mime="application/zip",
        )
        st.write("Included reports:")
        for name in st.session_state.get("batch_names", []):
            st.write(f"- {name}")
    elif st.session_state.report_text:
        st.header("📄 Comprehensive Threat Intelligence Report")
        st.caption(f"Report generated: {st.session_state.report_date}")
        report = st.session_state.report_text
        canonical_titles = [
            "Input Summary", "Threat Confidence", "Key Findings", "Quick Assessment",
            "Suspected IoC Core Attributes", "Reputation Analysis", "Network Behaviour Patterns",
            "Associated Activities", "Associated Campaigns", "Related Indicators",
            "Detection Signatures", "Recommendations", "Network Controls", "Endpoint Protection", "References"
        ]
        def normalize_header(header_text):
            clean = header_text.strip().lower()
            clean = re.sub(r"^\d+[\.\)]?\s*", "", clean)
            clean = re.sub(r"[:*\-]+", "", clean)
            clean = clean.strip()
            for canon in canonical_titles:
                if clean.startswith(canon.lower()):
                    return canon
            return None
        header_regex = re.compile(r"^\s*[*#\-]*\s*\d*[\.\)]?\s*([A-Za-z][\w\s/&-]{3,})\s*[:*\-]*\s*$", re.MULTILINE)
        matches = [(m.start(), m.end(), m.group(1)) for m in header_regex.finditer(report)]
        sections = {title: "Not available." for title in canonical_titles}
        for i, (start, end, raw_header) in enumerate(matches):
            canon_title = normalize_header(raw_header)
            if not canon_title:
                continue
            content_start = end
            content_end = matches[i + 1][0] if i + 1 < len(matches) else len(report)
            section_body = report[content_start:content_end].strip()
            repeated_header_pattern = re.compile(rf"^\s*[*#\-]*\s*{re.escape(raw_header)}\s*[:*\-]*\s*", re.IGNORECASE)
            section_body = repeated_header_pattern.sub("", section_body).strip()
            sections[canon_title] = section_body
        threat_conf_match = re.search(r"\*\*Threat Confidence\*\*\s*:?\s*\n?(\d+)", report)
        threat_confidence = int(threat_conf_match.group(1)) if threat_conf_match else "-"
        with st.expander("🔍 Executive Summary", expanded=True):
            cols = st.columns(3)
            cols[0].metric("Indicator Analyzed", st.session_state.ioc_input)
            cols[1].metric("Threat Confidence", threat_confidence)
            st.markdown(f"""
                **Key Findings:**
                {format_key_findings(sections['Key Findings'])}
                **Quick Assessment:**
                {sections['Quick Assessment']}
                """)
            sources = extract_vt_tf_sections(sections['Key Findings'])
            vt_text = sources['virustotal']
            tf_text = sources['threatfox']
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
                """)
    # Improved Associated Campaigns block
                if sections['Associated Campaigns'] and "not available" not in sections['Associated Campaigns'].lower():
                    st.markdown("""
                    <div style="background-color:#f7fafd; border-left:4px solid #184fa1; padding:1em; border-radius:10px; margin-bottom:1em;">
                    <b>Associated Campaigns:</b>
                    <ul style="margin-top:0.5em;">
                    """, unsafe_allow_html=True)
                    campaigns = [line.strip(" 1234567890).") for line in sections['Associated Campaigns'].splitlines() if line.strip()]
                    for camp in campaigns:
                        st.markdown(f"<li>{camp}</li>", unsafe_allow_html=True)
                    st.markdown("</ul></div>", unsafe_allow_html=True)
                else:
                    st.markdown("_No associated campaigns identified._")
            with tab3:
                st.subheader("Defensive Considerations")
                st.markdown(f"""
                    **Detection Signatures:**
                    {sections['Detection Signatures']}
                    **Network Controls:**
                    {sections['Network Controls']}
                    **Endpoint Protection:**
                    {sections['Endpoint Protection']}
                    """)
            with st.expander("🌐 Threat Context & References"):
                st.subheader("Related Indicators")
                st.markdown(format_related_indicators(sections['Related Indicators']))
                st.subheader("References")
                st.markdown(format_related_indicators(sections['References']))
            with st.expander("🛡️ Recommendations & Mitigations"):
                st.markdown(f"{sections['Recommendations']}")
            st.download_button(
                label="💾 Download Full Report",
                data=st.session_state.report_text,
                file_name="threat_intel_report.txt",
                mime="text/plain",
            )
    else:
        st.warning("No report has been generated yet. Please go to the 'Input' tab and run the analysis.")
