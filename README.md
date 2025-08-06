# SPF Lookup Tool - Email Security Analysis

A comprehensive Python tool for analyzing email security posture including SPF, DMARC, DKIM, and additional security records (BIMI, MTA-STS, TLS-RPT) for domains.

## Features

### Core Email Security Analysis
- **SPF (Sender Policy Framework)**: Parse and analyze SPF records, identify mechanisms, detect DNS lookup limits, and assess policy strength
- **DMARC (Domain-based Message Authentication)**: Evaluate DMARC policies, alignment settings, reporting configurations, and enforcement levels  
- **DKIM (DomainKeys Identified Mail)**: Discover DKIM selectors, validate public keys, analyze cryptographic strength, and check key configurations

### Advanced Security Records
- **BIMI (Brand Indicators for Message Identification)**: Validate BIMI records and VMC configurations for email logo authentication
- **MTA-STS (Mail Transfer Agent Strict Transport Security)**: Analyze MTA-STS policies for transport security enforcement
- **TLS-RPT (TLS Reporting)**: Check TLS reporting configurations for delivery monitoring

### Threat Intelligence
- **Domain Reputation**: Check domains against DNS-based blacklists and reputation services
- **Email Provider Detection**: Identify email service providers and their security implications
- **Subdomain Analysis**: Analyze subdomain security inheritance and policy gaps

### Comprehensive Recommendations
- **Security Recommendations**: Actionable advice for improving email security posture
- **Implementation Roadmap**: Phased approach for email security improvements
- **Cross-Protocol Analysis**: Identify conflicts and gaps between email security protocols

## Installation

### Prerequisites
- Python 3.7 or higher
- pip package manager

### Install Dependencies
```bash
pip install -r requirements.txt
```

### Required Packages
- `dnspython>=2.4.0` - DNS resolution and queries
- `requests>=2.31.0` - HTTP requests for MTA-STS policy fetching
- `colorama>=0.4.6` - Cross-platform colored terminal text
- `rich>=13.0.0` - Rich text and beautiful formatting
- `cryptography>=41.0.0` - Cryptographic operations for DKIM key analysis

## Usage

### Basic Analysis
Analyze a single domain with console output:
```bash
python lookup.py example.com
```

### Verbose Output
Enable detailed logging and debug information:
```bash
python lookup.py example.com --verbose
```

### JSON Output
Export results in machine-readable JSON format:
```bash
python lookup.py example.com --format json
```

### Save to File
Save JSON results to a file:
```bash
python lookup.py example.com --format json --output results.json
```

### Minimal JSON Output
Generate compact JSON with essential information only:
```bash
python lookup.py example.com --format json --minimal
```

## Command Line Options

```
usage: lookup.py [-h] [-v] [-f {console,json}] [-o OUTPUT] [--minimal] domain

Comprehensive email security analysis tool for SPF, DMARC, DKIM, and additional security records.

positional arguments:
  domain                Domain to analyze

options:
  -h, --help            show this help message and exit
  -v, --verbose         Enable verbose output
  -f, --format {console,json}
                        Output format (default: console)
  -o, --output OUTPUT   Output file (for JSON format)
  --minimal             Minimal JSON output with essential information only
```

## Output Formats

### Console Output
Rich, colorized console output with:
- Status indicators for each email security record
- Detailed configuration tables
- Security analysis with strength levels
- Color-coded warnings and errors
- Actionable recommendations

### JSON Output
Structured JSON output including:
- Complete record data with raw DNS records
- Detailed security analysis results
- Threat intelligence information
- Comprehensive recommendations
- Metadata with timestamps and tool version

### Minimal JSON Output
Compact JSON format with:
- Essential security status for each protocol
- High-level recommendations
- Minimal metadata for integration use cases

## Example Analysis

```bash
$ python lookup.py github.com

Analyzing email security for: github.com
=====================================

┌─ SPF Record ─────────────────────────────────────────┐
│ Status: ✓ Valid                                      │
│ Record: v=spf1 ip4:192.30.252.0/22 include:_spf.... │
│ DNS Lookups: 4/10                                    │
└──────────────────────────────────────────────────────┘

┌─ DMARC Policy ───────────────────────────────────────┐
│ Status: ✓ Valid                                      │
│ Policy: reject                                       │
│ Record: v=DMARC1; p=reject; rua=mailto:dmarc@...    │
└──────────────────────────────────────────────────────┘

┌─ DKIM Records ───────────────────────────────────────┐
│ Found Selectors: 2                                   │
│ Valid Selectors: 2                                   │  
│ Selectors: s1, s2                                    │
└──────────────────────────────────────────────────────┘

┌─ Security Recommendations ──────────────────────────┐
│ • Domain has excellent email security configuration │
│ • All major email authentication protocols enabled  │
│ • Strong DMARC enforcement policy in place          │
└──────────────────────────────────────────────────────┘
```

## Architecture

### Core Components
- `core/dns_analyzer.py` - DNS query engine for email security records
- `core/spf_parser.py` - SPF record parsing and analysis logic
- `core/dmarc_parser.py` - DMARC policy evaluation engine
- `core/dkim_validator.py` - DKIM discovery and validation system
- `core/additional_records.py` - BIMI, MTA-STS, TLS-RPT record processing

### Enrichment Modules  
- `enrichment/threat_intel.py` - Domain reputation and threat intelligence
- `enrichment/recommendations.py` - Security recommendation generation

### Output Formatters
- `output/console.py` - Rich console output formatting
- `output/json_export.py` - JSON export with multiple format options

## Security Analysis Levels

### SPF Analysis Levels
- **Strict**: Uses `-all` (hard fail) mechanism
- **Moderate**: Uses `~all` (soft fail) mechanism  
- **Permissive**: Uses `?all` (neutral) mechanism
- **Dangerous**: Uses `+all` (pass all) or misconfigured
- **Incomplete**: Missing `all` mechanism

### DMARC Analysis Levels
- **Strict**: Policy set to `reject`
- **Moderate**: Policy set to `quarantine`
- **Monitoring**: Policy set to `none` (monitoring only)
- **None**: No DMARC policy found

### DKIM Analysis Levels
- **Strong**: RSA-2048+ or Ed25519 keys
- **Moderate**: RSA-1024 keys
- **Weak**: Sub-1024 bit keys
- **None**: No valid DKIM records found

## Common Use Cases

### Security Assessment
Evaluate the email security posture of your domain:
```bash
python lookup.py yourdomain.com --verbose
```

### Compliance Auditing
Generate JSON reports for compliance documentation:
```bash
python lookup.py yourdomain.com --format json --output audit-report.json
```

### Automated Monitoring
Integrate with monitoring systems using minimal JSON output:
```bash
python lookup.py yourdomain.com --format json --minimal | your-monitoring-tool
```

### Security Consulting
Analyze client domains and generate comprehensive recommendations:
```bash
python lookup.py client-domain.com > security-assessment.txt
```

## Troubleshooting

### DNS Resolution Issues
If DNS queries fail, check:
- Network connectivity and DNS server configuration
- Domain name spelling and formatting
- Firewall rules allowing DNS queries

### Missing Dependencies
Install all required packages:
```bash
pip install -r requirements.txt
```

### Permission Errors
For output file creation issues:
```bash
# Ensure write permissions to output directory
ls -la /path/to/output/directory
```

## Contributing

### Development Setup
1. Clone the repository
2. Install dependencies: `pip install -r requirements.txt`
3. Run tests: `python -m pytest tests/`
4. Follow PEP 8 style guidelines

### Adding New Features
- Email security record parsers go in `core/`
- Threat intelligence sources go in `enrichment/`
- Output formatters go in `output/`
- Update documentation and examples

## License

This tool is provided for educational and security assessment purposes. Use responsibly and in accordance with applicable laws and regulations.

## Security Considerations

This tool performs DNS queries and HTTP requests to analyze email security configurations. It does not:
- Send emails or test actual email delivery
- Perform any actions that could be considered scanning or probing
- Store or transmit sensitive domain information
- Require elevated privileges or special permissions

The tool is designed for legitimate security assessment and compliance purposes.