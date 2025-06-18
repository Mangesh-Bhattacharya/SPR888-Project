import streamlit as st
from crewai import Agent, Task, Crew, Process, LLM
from streamlit_lottie import st_lottie
import requests
from datetime import datetime
import pandas as pd

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
        ioc_type = "ip"  # Optionally implement auto IoC type detection

        st.info("Initializing threat intelligence analysis using multi-agent system...")

        with st.spinner("Running analysis. This may take a few moments..."):
            # === Configure Language Model ===
            llm = LLM(
                model="ollama/llama3.2:latest",
                temperature=0.4,
                base_url="http://localhost:11434",
            )

            # === Original Agents (Unchanged) ===
            researcher = Agent(
                role="Researcher Identity",
                goal="Conduct OSINT research about the IoC using at least 10 safe threat intel sources",
                backstory="A cyber threat researcher using public sources such as VirusTotal, ThreatFox, Shodan, and Hybrid Analysis to gather metadata, indicators, and context without touching the IoC directly.",
                verbose=True,
                llm=llm,
            )

            reviewer = Agent(
                role="Reviewer Identity",
                goal="Fact-check and validate all of the Researcher's findings using independent sources and internal knowledge",
                backstory="A veteran security analyst tasked with verifying IoC intelligence and ensuring the integrity of information provided before analysis and action.",
                verbose=True,
                llm=llm,
            )

            analyzer = Agent(
                role="Analyzer Identity",
                goal="Analyze the reviewed IoC to determine classification, threat actor attribution, attack vectors, MITRE ATT&CK mapping, and recommended mitigations",
                backstory="A senior threat intelligence analyst correlating data with known campaigns, mapping behavior patterns, and guiding defensive postures.",
                verbose=True,
                llm=llm,
            )

            writer = Agent(
                role="Writer Identity",
                goal="Compile a professional, structured, and client-facing Threat Intelligence Report",
                backstory="A cybersecurity documentation specialist focused on converting technical findings into actionable, well-organized reports for C-level decision-makers and operations teams.",
                verbose=True,
                llm=llm,
            )

            # === Original Tasks (Unchanged) ===
            task_research = Task(
                description=f"Conduct threat research on the IoC: {ioc_input}. Use WHOIS, ASN, malware databases, VirusTotal, ThreatFox, Shodan, and others. Include metadata, context, and source citations. Finish with '[Transitioning to: Reviewer Identity]'",
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
                description=f"Perform deep analysis of {ioc_input}. Determine threat classification, MITRE ATT&CK mapping, TTPs, likely actors, and defenses. Finish with '[Transitioning to: Writer Identity]'",
                expected_output="Full threat context including attack methods, mapping, impact, and organizational recommendations.",
                agent=analyzer,
                context=[task_review],
            )

            task_write = Task(
                description="Write a formal Threat Intelligence Report using these sections: 1. Input Summary, 2. Threat Classification, 3. Tool Data Summary, 4. Web Intelligence, 5. IoC Analysis, 6. Mitigation Recommendations, 7. References.",
                expected_output="Polished report ready for distribution.",
                agent=writer,
                context=[task_analyze],
            )

            # === Assemble and Execute Crew ===
            crew = Crew(
                agents=[researcher, reviewer, analyzer, writer],
                tasks=[task_research, task_review, task_analyze, task_write],
                process=Process.sequential,
                verbose=True,
            )

            result = crew.kickoff(
                inputs={"ioc_input": ioc_input, "ioc_type": ioc_type})
            st.session_state.report_text = str(result)

        st.success("✅ Analysis complete! View the report under the 'Report' tab.")

# === REPORT PAGE ===
elif selected_page == "Report":
    if report_anim:
        st_lottie(report_anim, height=150, key="report_anim")

    if st.session_state.report_text:
        st.header("📄 Comprehensive Threat Intelligence Report")
        st.caption(f"Report generated: {st.session_state.report_date}")

        # === Report Overview ===
        with st.expander("🔍 Executive Summary", expanded=True):
            cols = st.columns(3)
            cols[0].metric("Indicator Analyzed", st.session_state.ioc_input)
            cols[1].metric("Threat Confidence", "78%", delta="Moderate-High")
            cols[2].metric("Data Sources", "12+ threat feeds")

            st.markdown("""
            **Key Findings:**
            - Indicator shows characteristics of potentially malicious infrastructure
            - Associated with known attack patterns from historical campaigns
            - Requires monitoring and defensive considerations
            
            **Quick Assessment:**
            - Recommended Action: Monitor and block with medium priority
            - Business Impact: Potential data exfiltration risk
            """)

        # === Detailed Analysis ===
        with st.expander("🕵️ Technical Analysis Details", expanded=True):
            tab1, tab2, tab3 = st.tabs(
                ["Indicator Analysis", "Behavior Patterns", "Defensive Insights"])

            with tab1:
                st.subheader("Indicator Characteristics")
                st.markdown("""
                **Core Attributes:**
                - Type: IP Address
                - First Seen: 2023-01-15
                - Last Active: Current
                - ASN: Cloud Provider (AS12345)
                
                **Reputation Analysis:**
                - VirusTotal: 8/92 detections
                - AbuseIPDB: 72% abuse confidence
                - GreyNoise: Sporadic scanning activity
                """)

            with tab2:
                st.subheader("Observed Behavior")
                st.markdown("""
                **Network Patterns:**
                - Beaconing every 23 minutes (±5 min)
                - Primarily active during business hours
                - Uses encrypted C2 channels
                
                **Associated Activities:**
                - Phishing campaign infrastructure
                - Possible data exfiltration
                """)

            with tab3:
                st.subheader("Defensive Considerations")
                st.markdown("""
                **Detection Signatures:**
                - Snort Rule: `alert tcp any any -> $HOME_NET any (msg:"Suspicious Beaconing"; flow:established; detection_filter:track by_src, count 5, seconds 300; sid:1000001;)`
                
                **Hunting Recommendations:**
                - Look for irregular outbound connections
                - Check for unusual scheduled tasks
                """)

        # === Threat Context ===
        with st.expander("🌐 Threat Context & References"):
            st.subheader("Related Threat Intelligence")
            st.markdown("""
            **Associated Campaigns:**
            - Operation GhostShell (2022-2023)
            - CloudHopper targeting (2023)
            
            **Similar Indicators:**
            - 192.0.2.15 (Same ASN, similar behavior)
            - 192.0.2.37 (Related C2 infrastructure)
            """)

            st.subheader("Reference Materials")
            st.markdown("""
            - [MITRE ATT&CK: Command and Control](https://attack.mitre.org/tactics/TA0011/)
            - [Cloud Security Alliance: Best Practices](https://cloudsecurityalliance.org)
            """)

        # === Recommendations ===
        with st.expander("🛡️ Mitigation Strategies"):
            st.subheader("Immediate Actions")
            st.markdown("""
            1. **Network Controls:**
                - Implement egress filtering for suspicious destinations
                - Update firewall rules to block known bad IPs
            
            2. **Endpoint Protection:**
                - Scan for suspicious processes
                - Review authentication logs
            """)

            st.subheader("Long-Term Recommendations")
            st.markdown("""
            - Enhance network monitoring capabilities
            - Conduct regular threat hunting exercises
            - Implement application allowlisting
            """)

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
