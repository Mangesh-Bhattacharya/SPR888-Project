from crewai import Agent, Task, Crew, Process
from crewai import LLM

# === Step 1: Get user input ===
ioc_input = input("Enter the suspected IoC (IP, domain, hash, email, or attacker name): ").strip()
ioc_type = "ip"  # You can add detection logic later if needed

# === Step 2: LLM Setup with explicit base_url ===
llm = LLM(
    model="ollama/llama3.2:latest",
    temperature=0.7,
    base_url="http://localhost:11434"  # Default for local Ollama
)

# === Step 3: Define agents ===

researcher = Agent(
    role="Researcher Identity",
    goal="Conduct OSINT research about the IoC using at least 10 safe threat intel sources",
    backstory="Professional Threat Intelligence Researcher using VirusTotal, ThreatFox, Shodan, OTX, etc. Never interacts with the IoC directly.",
    verbose=True,
    llm=llm
)

reviewer = Agent(
    role="Reviewer Identity",
    goal="Fact-check and verify all of the Researcher's findings using open sources and model knowledge",
    backstory="Expert Reviewer who ensures the accuracy and integrity of threat research. Cross-checks sources and confirms validity.",
    verbose=True,
    llm=llm
)

analyzer = Agent(
    role="Analyzer Identity",
    goal="Analyze the reviewed IoC to determine threat classification, MITRE ATT&CK mapping, TTPs, and mitigation strategies",
    backstory="Threat Intelligence Analyst specializing in correlating IoC behaviors with real attacks and recommending defense strategies.",
    verbose=True,
    llm=llm
)

writer = Agent(
    role="Writer Identity",
    goal="Compile a professional threat intelligence report using the structured template",
    backstory="Security report writer creating clear, accurate, and actionable documentation for defenders.",
    verbose=True,
    llm=llm
)

# === Step 4: Define tasks with expected_output ===

task_research = Task(
    description=(
        f"You are the Researcher Identity. Conduct deep threat intelligence research on the following IoC: {ioc_input}.\n"
        "Use at least 10 open sources and safe tools (e.g., VirusTotal, ThreatFox, Hybrid Analysis, Censys).\n"
        "Collect WHOIS, ASN, malware associations, detection data, sandbox verdicts, tags, blog mentions, forum citations.\n"
        "Finish by saying: **[Transitioning to: Reviewer Identity]**"
    ),
    expected_output="Thoroughly researched report including data from at least 10 threat intel sources, clearly cited and relevant to the IoC.",
    agent=researcher
)

task_review = Task(
    description=(
        "You are the Reviewer Identity. Fact-check and validate all claims made by the Researcher using independent sources and model knowledge.\n"
        "Correct any inaccuracies and preserve verified data.\n"
        "Finish by saying: **[Transitioning to: Analyzer Identity]**"
    ),
    expected_output="Fact-checked and corrected version of the research data, ready for deep analysis.",
    agent=reviewer,
    context=[task_research]
)

task_analyze = Task(
    description=(
        f"You are the Analyzer Identity. Analyze the reviewed information about {ioc_input}. Identify threat classification, associated malware, attack vectors, MITRE ATT&CK mapping, and defense recommendations.\n"
        "Provide technical and organizational mitigation suggestions.\n"
        "Finish by saying: **[Transitioning to: Writer Identity]**"
    ),
    expected_output="Detailed analysis of the IoC including threat context, MITRE ATT&CK mapping, threat actor attribution, and actionable mitigations.",
    agent=analyzer,
    context=[task_review]
)

task_write = Task(
    description=(
        "You are the Writer Identity. Use the collected data to write a professional Threat Intelligence Report using the following headers:\n"
        "1. Input Summary\n2. Threat Classification\n3. Tool Data Summary\n4. Web Search Intelligence\n"
        "5. IoC Correlation and Analysis\n6. Mitigation and Detection Recommendations\n7. Appendix / References Used\n"
        "Ensure clarity, structure, and at least 1000 words of rich, useful content."
    ),
    expected_output="Final comprehensive threat intelligence report in structured format with all data from the research, review, and analysis phases.",
    agent=writer,
    context=[task_analyze]
)

# === Step 5: Create and run the crew ===

crew = Crew(
    agents=[researcher, reviewer, analyzer, writer],
    tasks=[task_research, task_review, task_analyze, task_write],
    process=Process.sequential,
    verbose=True
)

result = crew.kickoff(inputs={"ioc_input": ioc_input, "ioc_type": ioc_type})

# === Step 6: Output final report ===
print("\n\n✅ FINAL REPORT:\n")
print(result)