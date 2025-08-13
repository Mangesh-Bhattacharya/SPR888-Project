# Threat Intelligence Automated Research and Analysis AI Tool

A Streamlit web application for automated **threat intelligence research and analysis**.  
Given Indicators of Compromise (IoCs) — **IP addresses, domains, and file hashes** — the app queries **VirusTotal** and **ThreatFox**, and cross-references **local datasets** (included) to surface matches with surrounding context. It supports **single IoC lookups** and **batch analysis** with results available for **download**.

> **Security note:** Never commit your API keys to GitHub. This README uses placeholders (e.g., `YOUR_VT_API_KEY`) instead of genuine keys.

---

## Features

- **Single IoC analysis** for IPs, domains, and file hashes (MD5/SHA1/SHA256).
- **Batch analysis**: paste many IoCs (one per line) or upload a `.txt` file.
- **VirusTotal & ThreatFox** lookups via their public APIs.
- **Local dataset search** (files included alongside the app) with **contextual matches**.
- **Reports** view to explore results and **download** outputs.
- Built with **Python 3.10+** and **Streamlit**.

---

## Requirements

- **OS:** Windows 10 or 11 (tested).  
- **Python:** 3.10 or above (installed and added to `PATH`).  
- **Network:** Internet connectivity for VirusTotal and ThreatFox.  
- **API keys:** VirusTotal & ThreatFox.  
- **Editor:** Visual Studio Code (recommended).  
- **Datasets:** Files included in the project folder.

> The app is contained in `spr888.py` and expects the dataset files to live in the same project directory (or a path you configure).

---

## Quick Start (Windows / VS Code)

### 1) Open the project in VS Code
- **File → Open Folder…** and select the folder containing:
  - `spr888.py`
  - Dataset files (included)

### 2) Open a **Command Prompt** terminal in VS Code
The app’s example commands use **cmd** (not PowerShell) for environment variables:
- VS Code → **Terminal → New Terminal**
- If it opens PowerShell, type `cmd` to switch, or use the dropdown ▾ and choose **Command Prompt**.

### 3) (Recommended) Create a virtual environment
```cmd
python -m venv .venv
.venv\Scripts\activate
```
> If you prefer PowerShell: `.\.venv\Scripts\Activate.ps1`  
> On macOS/Linux: `python3 -m venv .venv && source .venv/bin/activate`

### 4) Install dependencies
```cmd
python -m pip install --upgrade pip
pip install streamlit requests chardet streamlit-lottie crewai python-dotenv pandas beautifulsoup4
```

### 5) Configure API keys (do **not** hardcode in code)

**Option A — .env file (recommended)**  
Create a file named `.env` in the project root:
```
VT_API_KEY=YOUR_VT_API_KEY
TF_API_KEY=YOUR_TF_API_KEY
```
The app uses `python-dotenv` to load these automatically at runtime.

**Option B — Environment variables (session only)**  
From **cmd** in VS Code, set for the current terminal session:
```cmd
set VT_API_KEY=YOUR_VT_API_KEY
set TF_API_KEY=YOUR_TF_API_KEY
```
> For persistent variables on Windows, use `setx` (new shells only):  
> `setx VT_API_KEY "YOUR_VT_API_KEY"` and `setx TF_API_KEY "YOUR_TF_API_KEY"`

**PowerShell (session only):**
```powershell
$env:VT_API_KEY = "YOUR_VT_API_KEY"
$env:TF_API_KEY = "YOUR_TF_API_KEY"
```

**macOS/Linux (session only):**
```bash
export VT_API_KEY="YOUR_VT_API_KEY"
export TF_API_KEY="YOUR_TF_API_KEY"
```

### 6) Point the app at your datasets
Open `spr888.py` and set the dataset folder path:
```python
# Example Windows path (use a raw string for backslashes)
DATASET_PATH = r"D:\Projects\SPR888\Datasets"

# Example macOS/Linux path
# DATASET_PATH = "/Users/you/Projects/SPR888/Datasets"
```
> If your datasets live **beside** `spr888.py`, you can keep the default or set `DATASET_PATH` to that folder.

### 7) Run the app
```cmd
python -m streamlit run spr888.py
```
Your browser should open to **http://localhost:8501** automatically.

---

## Using the App

### Single IoC Analysis
- Enter one IP/domain/file hash.
- Click **Analyze IOC** to generate a report (remote lookups + local dataset matches).

### Multiple IoC Analysis
- Paste many IoCs (one per line) **or** upload a `.txt` file.
- Click **Analyze Multiple IOCs**; results render per IoC.

### Reports
- Open the **Reports** tab to review generated reports, view local dataset matches with surrounding context, and **download** the results.

### Quick smoke test
Use a public, benign example such as `8.8.8.8` in **Single IoC Analysis** to verify the app flow.

---

## Data Sources

- **VirusTotal API** — reputation, detections, and metadata for IPs/domains/hashes.  
- **ThreatFox API** — community-sourced IoCs and context.

> Respect rate limits and Terms of Service for each provider. Consider caching for larger batch jobs.

---

## Project Structure

```
project-root/
├─ spr888.py                # Streamlit application
├─ datasets/                 # Local datasets (example folder name)
├─ .env                      # (optional) API keys; never commit to VCS
└─ README.md                 # This file
```

---

## Security & Privacy

- **Do not** paste genuine API keys into README/issues or commit them to the repo.
- Add `.env` (and any file containing secrets) to `.gitignore`.
- Verify that the IoCs you test are safe to query per your organization’s policies.
- Be mindful of **PII** or sensitive logs if you add custom datasets.

---

## Troubleshooting

- **Module not found (e.g., streamlit):** Re-run dependency installation in the **active** virtual environment.
- **Dataset not found:** Verify `DATASET_PATH` and folder contents; ensure paths are correct on your OS.
- **Port in use/browser won’t open:** Run on a different port:  
  `python -m streamlit run spr888.py --server.port 8502`
- **API auth errors:** Ensure environment variables are set in the **same terminal** you use to run Streamlit (or use `.env`).

---

## Roadmap/Ideas

- Optional output formats (CSV/JSON) for batch results.
- Caching layer for API responses to reduce rate limit pressure.
- Additional threat intel sources (AbuseIPDB, OTX, etc.).
- Dockerfile for reproducible runs.
- Cross-platform setup docs (macOS/Linux specifics).

---

## Contributing

Issues and PRs are welcome. Please avoid including any genuine API keys or sensitive IoCs in tickets or sample data.

---

## License

Specify your license of choice, e.g., MIT or Apache-2.0.

---

## Contact

- [Mangesh Bhattacharya](mailto:mabhattacharya@myseneca.ca)
- [Artem Gaynetdinov](mailto:agaynetdinov@myseneca.ca)
- [Lekshmi Balan](mailto:lbalan@myseneca.ca)
