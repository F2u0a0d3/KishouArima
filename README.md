# 🔍 KishouArima

A modular and extensible Python-based reconnaissance agent designed for Red Teams, and Bug Bounty Hunters. Built with compatibility for the **Google ADK (Agent Development Kit)**, it leverages a rich plugin system for automated recon workflows.

## ✨ Features

- 🌐 **ASN to IP Range Mapping**: Uses RIPEstat, BGP.he.net, and ipinfo.io
- 🕵️ **Subdomain Enumeration**: Supports tools like `subfinder`, `bbot`, `skanuvaty`, `shosubgo`, `scilla`, and `csprecongo`
- 🌍 **Archived URL Collection**: Via `waymore`, `gau`, and `waybackurls`
- 🔬 **JavaScript Link Analysis**: Extract URLs using `LinkFinder`
- 🧪 **Broken Link Scanning**: Using `broken-link-checker (blc)`
- 🧭 **Web Crawling**: Katana-based crawling with JavaScript parsing
- 🚪 **Port Scanning**: With `nmap` and `smap` support
- ☁️ **Cloud Recon**: Identify cloud-related IP blocks (AWS, Google, Microsoft, etc.) using domain matching on IPv4 SNI lists
- 💾 **Structured Results**: Auto-saves JSON/text output to clean directories with timestamps

## ⚙️ Tech Stack

- Language: **Python 3.11+**
- Optional: **Google ADK Integration**, `requests`, `bs4`, subprocess tools
- External Dependencies: Several recon tools (see below)

## 🛠 External Tool Dependencies

- `subfinder`, `bbot`, `waymore`, `gau`, `waybackurls`, `nmap`, `smap`, `katana`, `blc`, `linkfinder`, `shosubgo`, `skanuvaty`, `scilla`, `csprecongo`

## ⚠️ Note on Output Limitation

Some tools may not display the full results directly in the console or return data due to the large size of the output. This is intentionally designed to prevent excessive memory or token usage when integrating with LLMs or automated agents.

📩 For suggestions, bug reports, or feedback, feel free to reach out:

Email: f2u0a0d3@gmail.com

Discord: @f2u0a0d3
