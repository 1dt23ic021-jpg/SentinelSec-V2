# SentinelSec V2

**A Python-Based Cybersecurity Assessment and Reporting Tool**

SentinelSec V2 is a modular cybersecurity project designed to perform network and web assessments, analyze security findings, evaluate risks, and generate structured security reports.

## Features

- **Network Scanning:** Identify accessible ports and gather service information.
- **Service Detection:** Detect services and retrieve available service banners.
- **Web Assessment:** Perform web security checks against authorized targets.
- **Password Security Auditing:** Evaluate password security characteristics.
- **Traffic Analysis:** Analyze packet captures for network traffic insights.
- **Findings & Risk Engine:** Organize assessment findings and support risk analysis.
- **Automated Reporting:** Generate HTML and JSON security reports.
- **Assessment History:** Store and compare previous assessment results.
- **Port & Service Comparison:** Identify changes between assessments.
- **Modular Architecture:** Separate modules for networking, web assessment, authentication, traffic analysis, and reporting.

## Technology Stack

- Python
- HTML
- JSON
- Git and GitHub
- Python testing tools

## Project Structure

```text
SentinelSec-V2/
├── main.py
├── modules/
│   ├── authentication/
│   ├── network/
│   ├── reporting/
│   ├── traffic/
│   └── web/
├── tests/
├── utils/
├── requirements.txt
├── test_html_report.py
├── test_scan_history.py
├── test_v2_report.py
├── README.md
└── .gitignore
```

## Installation

**1. Clone the repository**

```bash
git clone https://github.com/1dt23ic021-jpg/SentinelSec-V2.git
cd SentinelSec-V2
```

**2. Create a virtual environment**

Windows PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

**3. Install dependencies**

```bash
python -m pip install -r requirements.txt
```

## Usage

Start by checking the available command-line options and usage instructions in `main.py`:

```bash
python main.py --help
```

If the application does not support `--help`, consult the argument parsing and entry-point code in `main.py` for the correct invocation.

Use only targets and network captures you own or have explicit permission to assess.

## Testing

Run the project's tests using Python's unittest discovery:

```bash
python -m unittest discover -s tests -v
```

Additional standalone test scripts are available in the project root. Run them according to their contents and dependencies.

## Security & Responsible Use

SentinelSec V2 is intended for educational purposes, authorized security assessments, and defensive security research.

- Obtain authorization before scanning systems or networks.
- Use packet captures that you are permitted to analyze.
- Protect credentials, sensitive findings, and generated reports.
- Follow applicable laws and organizational security policies.

## Project Status

SentinelSec V2 includes modular assessment components, findings and risk analysis, report generation, assessment history, and port/service comparison.

The project is under active development, with further improvements to assessment comparison and reporting planned.

## Author

Developed as a cybersecurity portfolio project to explore network security, web assessment, risk analysis, and automated reporting.

## License

No license has been added yet. Unless a license is added, the repository's code remains subject to applicable copyright law.