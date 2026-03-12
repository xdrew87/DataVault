# DataVault - Multi-Source Intelligence Collector

A professional, modern GUI application for collecting and analyzing data from multiple cybersecurity and OSINT sources. Built with PyQt6 for a clean, responsive interface.

![Version](https://img.shields.io/badge/version-1.0.0-blue)
![Python](https://img.shields.io/badge/python-3.8%2B-green)
![License](https://img.shields.io/badge/license-Proprietary-red)

## Features

✨ **5 Powerful Modules:**

- 🔍 **IP/Domain Lookup** - Resolve IPs, reverse DNS, basic geolocation
- ⚠️ **Breach Checker** - Check if emails/domains have been breached (HIBP API)
- 🕷️ **Web Scraper** - Extract content, metadata, and structure from websites
- 🛡️ **Vulnerability Scanner** - Analyze security headers and detect common issues
- 📊 **VPS Monitor** - Check server status and connectivity

📊 **Smart Features:**

- Multi-threaded execution (non-blocking UI)
- Real-time progress indicators
- One-click data export (JSON, CSV, PDF)
- Professional dark/light theme support
- Responsive, modern interface
- Error handling and logging

## Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/xdrew87/DataVault.git
cd DataVault

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### Running the Application

```bash
python main.py
```

## Usage

### IP/Domain Lookup Tab
1. Enter an IP address or domain name
2. Click "Lookup"
3. View results (IP, reverse DNS, etc.)
4. Export results as JSON or CSV

### Breach Checker Tab
1. Enter an email address or domain
2. Click "Check"
3. View breach history (if any)
4. Export results

### Web Scraper Tab
1. Enter a website URL
2. Click "Scrape"
3. View extracted content and metadata
4. Export page data

### Vulnerability Scanner Tab
1. Enter target URL or IP
2. Click "Scan"
3. Review security score and findings
4. Export scan results

### VPS Monitor Tab
1. Enter server hostname or IP
2. Click "Check Status"
3. View server health and response time
4. Export results

## Configuration

### API Keys (Optional)

Some modules work without API keys, others are optional:

```json
{
    "ipinfo_token": "optional_for_enhanced_ip_data",
    "virustotal_api_key": "optional_for_advanced_scanning"
}
```

**IP/Domain Lookup** uses `https://suicixde.com/api/geoip/` - no API key required

Or set environment variables:
```bash
export IPINFO_TOKEN="your_token"
export VIRUSTOTAL_API_KEY="your_api_key"
```

## Project Structure

```
DataVault/
├── main.py                 # Entry point
├── requirements.txt        # Dependencies
├── .gitignore              # Git ignore rules
├── config/
│   └── config.py           # Configuration & settings
├── core/
│   ├── collectors.py       # Data collection modules
│   └── export.py           # Export functionality
├── ui/
│   ├── main_window.py      # Main window & styling
│   └── tabs.py             # Tab definitions & layouts
└── README.md               # This file
```

## Security

⚠️ **Report Security Issues:** abuse@osintintelligence.xyz

Please see [SECURITY.md](SECURITY.md) for:
- How to report vulnerabilities responsibly
- Security best practices for using this tool
- Dependency update guidelines
- Responsible use guidelines

## Technologies

- **PyQt6** - Modern GUI framework
- **Requests** - HTTP client
- **BeautifulSoup4** - Web scraping
- **Pandas** - Data handling
- **ReportLab** - PDF generation
- **python-dotenv** - Environment variables

## API Sources

- **GeoIP Lookup** - suicixde.com/api/geoip (free, no auth required)
- **Have I Been Pwned** - Breach data (free, no auth required)
- **IPinfo.io** - Enhanced IP geolocation (optional token)
- **VirusTotal** - Malware/URL analysis (optional API key)

## Current Features ✅

- ✅ Professional dark theme by default
- ✅ Multi-threaded non-blocking UI
- ✅ Real-time progress indicators
- ✅ JSON, CSV, and PDF export
- ✅ GeoIP lookup without API keys
- ✅ Breach checking via HIBP
- ✅ Web content extraction
- ✅ Security header analysis
- ✅ Server connectivity monitoring

## Future Enhancements

- [ ] Database integration for result history
- [ ] Advanced filtering and search
- [ ] Batch processing (multiple targets)
- [ ] Caching for faster repeated queries
- [ ] API rate limiting management
- [ ] Scheduled scans
- [ ] Custom report generation

## Troubleshooting

### "ModuleNotFoundError: No module named 'PyQt6'"
```bash
pip install -r requirements.txt
```

### API not working?
- Check your API keys in `config/api_keys.json`
- Verify internet connectivity
- Check API rate limits

### Slow queries?
- Some APIs have rate limits
- Use caching for repeated queries (coming soon)
- Check your internet connection

## Contributing

This is a proprietary project. Contributions, modifications, and redistribution are not permitted.

For inquiries: abuse@osintintelligence.xyz

## License

This project is licensed under a Proprietary License - see [License.md](License.md) file for details.

Unauthorized copying, modification, distribution, or use is strictly prohibited.

## Disclaimer

This tool is for educational and authorized security testing only. Ensure you have permission before scanning or analyzing any systems. Unauthorized access to computer systems is illegal.

## Support

- 📧 Email: abuse@osintintelligence.xyz

---

**Proprietary Software - All Rights Reserved**

