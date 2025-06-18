import streamlit as st
from crewai import Agent, Task, Crew, Process, LLM
from streamlit_lottie import st_lottie
import requests
from datetime import datetime
import pandas as pd
import re

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
                goal="Classify the passed suspected IoC. Conduct OSINT research about the IoC using at least 10 safe threat intel sources",
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
            task_classify = Task(
                description=f"Classify the suspected IoC: {ioc_input} as one of the either: IP, file hash, url, email, or attacker name. IP value would be represented by 4 umerical values 0-255 split by periods '.'. File hash will be a unique value consisting of integers and letters in random order. URL would be a string of letters and ingeres followed by period '.' and ending with top level domain value. Email would be a combination of integers and letters followed by '@' and ending with domain value. Attacker's name should be a combination of letter's representing a name.",
                expected_output="A definitife classification for the suspected IoC: can either be one of the following: IP, file hash, url, email, or attacker name",
                agent=researcher,
            )

            task_research = Task(
                description=f"Conduct threat research on the IoC: {ioc_input}. Use WHOIS, ASN, malware databases, VirusTotal, ThreatFox, Shodan, and others. Include metadata, context, and source citations make sure to collect information on 1. Input Summary, 3. Key Findings, 5. Suspected IoC Core Attributes 6. Reputation Analysis 7. Network Behaviour Patterns 8. Associated Activities 9. Associated Campaigns 10. Related Indicators 11. Detection signatures 12. Recommendations 13. Network Controls 14. Endpoint Protection 15. References 16. References Amount . Finish with '[Transitioning to: Reviewer Identity]'",
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
                description=f"Perform deep analysis of {ioc_input}. Determine threat classification, threat confidence in perscentage value, MITRE ATT&CK mapping, TTPs, likely actors, and defenses. Make sure to cover for the following report 1. Input Summary, 2. Threat Confidence 3. Key Findings, 4. Quick Assessment, 5. Suspected IoC Core Attributes 6. Reputation Analysis 7. Network Behaviour Patterns 8. Associated Activities 9. Associated Campaigns 10. Related Indicators 11. Detection signatures 12. Recommendations 13. Network Controls 14. Endpoint Protection 15. References 16. References Amount . Never call a section 'References Used' call it only 'References'. Finish with '[Transitioning to: Writer Identity]' Make sure to bold every section name.",
                expected_output="Full threat context including attack methods, mapping, impact, and organizational recommendations. Provide analysis results. For the threat confidence level section provide only number from 0 to 100 without any wording",
                agent=analyzer,
                context=[task_review],
            )

            task_write = Task(
                description="Write a formal Threat Intelligence Report formatting it using stricly these sections and not any other: 1. Input Summary, 2. Threat Confidence 3. Key Findings, 4. Quick Assessment, 5. Suspected IoC Core Attributes 6. Reputation Analysis 7. Network Behaviour Patterns 8. Associated Activities 9. Associated Campaigns 10. Related Indicators 11. Detection signatures 12. Recommendations 13. Network Controls 14. Endpoint Protection. 15. References 16. References Amount Never call a section 'Threat Confidence Level' only 'Threat Confidence'.Never call a section 'References 'References Used' call it only 'References'. Make sure to bold every section name.",
                expected_output="Polished report ready for distribution using strictly the following sections: 1. Input Summary, 2. Threat Confidence 3. Key Findings, 4. Quick Assessment, 5. Suspected IoC Core Attributes 6. Reputation Analysis 7. Network Behaviour Patterns 8. Associated Activities 9. Associated Campaigns 10. Related Indicators 11. Detection signatures 12. Recommendations 13. Network Controls 14. Endpoint Protection. 15. References 16. References Amount  For the threat confidence level section provide only number from 0 to 100 without any wording. Never call a section 'Threat Confidence Level' only 'Threat Confidence'. Never call a section 'References 'References Used' call it only 'References'..Make sure to bold every section name.",
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
            print("Here's the report state result: "+st.session_state.report_text)
        st.success("✅ Analysis complete! View the report under the 'Report' tab.")

# === REPORT PAGE ===
elif selected_page == "Report":
    if report_anim:
        st_lottie(report_anim, height=150, key="report_anim")

    if st.session_state.report_text:
        st.header("📄 Comprehensive Threat Intelligence Report")
        st.caption(f"Report generated: {st.session_state.report_date}")

        report = st.session_state.report_text

        # --- Extract text sections using markdown-aware patterns ---
        def extract_section(title):
            pattern = rf"\*\*{re.escape(title)}\*\*\n+(.*?)(?=\n\*\*|\Z)"
            match = re.search(pattern, report, re.DOTALL)
            return match.group(1).strip() if match else "Not available."

        # --- Extract numerical threat confidence value ---
        threat_conf_match = re.search(r"\*\*Threat Confidence\*\*\s*:?\s*\n?(\d+)", report)
        threat_confidence = int(threat_conf_match.group(1)) if threat_conf_match else None

        # --- Extract other sections ---
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

        #DOESN'T WORK YET - ADJUST BY WEEK 9
        def clean_markdown_text(text):
            # Remove leading/trailing whitespace and standardize line breaks
            text = text.strip()
            text = re.sub(r'\n{2,}', '\n', text)  # Collapse multiple line breaks
            text = re.sub(r'^\*\s*', '- ', text, flags=re.MULTILINE)
            text = re.sub(r'\n\*\s*', '\n- ', text)  # Also handle mid-paragraph bullets
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

        # === Report Overview ===
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

        # === Detailed Analysis ===
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

        # === Threat Context ===
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

        # === Recommendations ===
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
