created by Deepseek:( 
# USB Killer Malware Analysis & Defense Tool

## 📌 Project Overview

This project provides a comprehensive technical analysis of the USB Killer malware along with defensive tools. The malware spreads via USB drives and exhibits dangerous behaviors including data exfiltration and persistence mechanisms. We offer both manual detection methods and automated removal solutions.

## 🚀 Key Features

### 🔍 Malware Analysis
• Propagation mechanism analysis (triple infection paths)
• Persistence technique research (registry autorun)
• Data exfiltration behavior analysis (file scanning logic)
• Encryption communication (Fernet implementation)

### 🛡️ Defense Tool Capabilities
• **Malicious process termination**: Kills all related malware processes
• **File cleanup**: Completely removes malicious files and directories
• **Registry repair**: Eliminates malicious autorun entries
• **USB scanning**: Detects and cleans infected USB drives
• **Real-time protection**: Monitors suspicious USB operations

## 🛠️ Technology Stack

• **Analysis Tools**: IDA Pro, Ghidra, x64dbg, Process Monitor
• **Development Languages**: Python (defense tool), Markdown (analysis reports)
• **Dependencies**: psutil, winreg, hashlib (Python defense tool)

## 📂 Project Structure

```
USB-Killer-Defender/
├── docs/                        # Documentation
│   ├── Technical_Analysis.md     # Detailed malware analysis
│   └── Defense_Guide.md          # Protection methodology
├── src/                         # Source code
│   ├── usb_defender.py          # Main defense tool
│   └── utils/                   # Utility modules
├── samples/                     # Malware samples (password protected)
│   └── README.md                # Sample handling instructions
├── requirements.txt             # Python dependencies
└── README.md                    # This document
```

## ⚙️ Installation & Usage

### Prerequisites
• Python 3.8+
• Windows OS (tested on Windows 10/11)
• Administrator privileges

### Quick Start
1. Clone the repository:
   ```bash
   git clone https://github.com/your-repo/USB-Killer-Defender.git
   cd USB-Killer-Defender
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Run the defense tool (as Administrator):
   ```bash
   python src/usb_defender.py
   ```

## 🛡️ Defense Tool Usage Options

| Command | Description |
|---------|-------------|
| `--scan` | Scan system for infections |
| `--clean` | Remove detected malware |
| `--monitor` | Enable real-time protection |
| `--check-usb` | Scan connected USB drives |
| `--verbose` | Show detailed output |

Example:
```bash
python src/usb_defender.py --scan --clean --verbose
```

## 📝 Analysis Highlights

1. **Propagation**:
   • Creates hidden folders named "资料库" (Document Library)
   • Drops malicious executables with innocent-looking names
   • Uses three-stage infection: folder → shortcut → VBS script

2. **Persistence**:
   • Adds registry entry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\USBCopy`
   • Targets multiple installation paths (AppData, D:\, Temp)

3. **Data Collection**:
   • Scans for files containing keywords: "机密", "重要", "财务" (Confidential, Important, Finance)
   • Skips files >100MB and certain extensions (.iso, .vhd)

## ⚠️ Important Notes

• Handle malware samples with extreme caution in isolated environments
• The defense tool requires Administrator privileges for full functionality
• Real-time monitoring may impact system performance slightly

## 🤝 Contributing

We welcome contributions! Please:
1. Fork the repository
2. Create your feature branch
3. Submit a pull request with detailed description

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 📧 Contact

For security-related issues, please contact: security@example.com

---

**Disclaimer**: This tool is for defensive purposes only. Use responsibly and only on systems you own or have permission to scan.
