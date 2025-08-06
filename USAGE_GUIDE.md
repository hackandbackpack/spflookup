# Usage Guide - SPF Lookup Tool

## Quick Start

### Basic Domain Analysis
```bash
python lookup.py example.com
```

This performs a comprehensive email security analysis and displays results in an easy-to-read console format.

## Understanding the Output

### SPF (Sender Policy Framework) Analysis

The SPF section shows:
- **Status**: Whether a valid SPF record exists
- **Record**: The raw SPF record from DNS
- **DNS Lookups**: Current count vs. the 10-lookup limit
- **Mechanisms**: Detailed breakdown of SPF mechanisms

#### SPF Qualifier Meanings
- **+** (Pass): Explicitly authorized sender
- **-** (Fail): Not authorized, reject the message  
- **~** (SoftFail): Not authorized, but don't reject
- **?** (Neutral): No policy statement

#### SPF Security Levels
- **Strict**: Uses `-all` for hard rejection of unauthorized senders
- **Moderate**: Uses `~all` for soft rejection (recommended starting point)
- **Permissive**: Uses `?all` or incomplete configuration
- **Dangerous**: Uses `+all` which allows any sender (security risk!)

### DMARC (Domain-based Message Authentication) Analysis

The DMARC section displays:
- **Policy**: Domain policy (none/quarantine/reject)
- **Subdomain Policy**: Policy for subdomains (if specified)
- **Alignment**: SPF and DKIM alignment requirements
- **Reporting**: Aggregate and failure report configurations

#### DMARC Policy Levels
- **p=none**: Monitoring mode, no enforcement
- **p=quarantine**: Suspicious messages quarantined
- **p=reject**: Unauthorized messages rejected

#### DMARC Tags Explained
- **rua**: Aggregate report email address
- **ruf**: Failure report email address
- **pct**: Percentage of messages to apply policy to
- **aspf/adkim**: SPF/DKIM alignment mode (r=relaxed, s=strict)

### DKIM (DomainKeys Identified Mail) Analysis

The DKIM section shows:
- **Discovered Selectors**: DKIM selectors found via common name probing
- **Key Information**: Cryptographic key details and strength
- **Validity**: Whether each DKIM record is properly configured

#### DKIM Key Strength
- **Strong**: RSA-2048+ bits or Ed25519 keys
- **Moderate**: RSA-1024 bits (consider upgrading)
- **Weak**: Sub-1024 bit keys (security risk)

### Additional Security Records

#### BIMI (Brand Indicators for Message Identification)
Shows whether your domain has brand logo authentication configured:
- **Logo URL**: Location of brand logo
- **VMC**: Verified Mark Certificate for enhanced validation

#### MTA-STS (Mail Transfer Agent Strict Transport Security)
Displays transport security policy:
- **Policy ID**: Current policy identifier
- **Mode**: enforce/testing/none
- **Max Age**: Policy cache duration

#### TLS-RPT (TLS Reporting)
Shows TLS failure reporting configuration:
- **Report URI**: Where TLS failure reports are sent

### Threat Intelligence

This section provides security context:
- **Reputation Status**: Overall domain reputation
- **Blacklist Status**: Results from DNS-based spam blacklists
- **Email Providers**: Identified email service providers
- **Security Notes**: Additional context and observations

### Recommendations

Actionable advice for improving your email security posture, prioritized by impact and implementation difficulty.

## Command Line Options

### Verbose Output (`-v, --verbose`)
```bash
python lookup.py example.com --verbose
```
Enables detailed logging including:
- DNS query debug information
- Record parsing details
- Error details and stack traces

### JSON Output (`--format json`)
```bash
python lookup.py example.com --format json
```
Outputs structured JSON data suitable for:
- Integration with other tools
- Automated processing
- Long-term storage and analysis

### Save Results (`--output filename`)
```bash
python lookup.py example.com --format json --output results.json
```
Saves analysis results to a file instead of displaying on screen.

### Minimal JSON (`--minimal`)
```bash
python lookup.py example.com --format json --minimal
```
Produces compact JSON output with essential information only, useful for:
- Monitoring systems
- API integrations  
- Resource-constrained environments

## Common Analysis Scenarios

### New Domain Setup

When setting up email security for a new domain:

1. **Start with Monitoring**:
   ```bash
   python lookup.py newdomain.com
   ```
   
2. **Implement Basic SPF**:
   - Add SPF record: `v=spf1 ~all` (start with soft fail)
   
3. **Add DMARC Monitoring**:
   - Add DMARC record: `v=DMARC1; p=none; rua=mailto:dmarc@newdomain.com`
   
4. **Configure DKIM**:
   - Set up DKIM signing with your email provider
   
5. **Re-analyze and Strengthen**:
   ```bash
   python lookup.py newdomain.com --verbose
   ```

### Security Assessment

For evaluating existing domain security:

1. **Comprehensive Analysis**:
   ```bash
   python lookup.py targetdomain.com --verbose
   ```

2. **Generate Report**:
   ```bash
   python lookup.py targetdomain.com --format json --output assessment.json
   ```

3. **Review Recommendations**: Focus on high-impact security improvements

### Monitoring and Compliance

For ongoing security monitoring:

1. **Regular Checks**:
   ```bash
   python lookup.py yourdomain.com --format json --minimal > daily-check.json
   ```

2. **Automated Integration**: Use JSON output with monitoring systems

3. **Trend Analysis**: Compare results over time for configuration drift

## Interpreting Recommendations

### Priority Levels

Recommendations are typically prioritized as:

1. **URGENT**: Security vulnerabilities requiring immediate attention
2. **High Priority**: Important security improvements
3. **Medium Priority**: Configuration optimizations
4. **Low Priority**: Advanced features and monitoring

### Common Recommendations

#### "Implement SPF record"
**Meaning**: No SPF record found
**Action**: Add `v=spf1 ~all` to your DNS TXT records
**Impact**: Prevents basic email spoofing

#### "Upgrade DMARC policy from 'none' to 'quarantine'"  
**Meaning**: DMARC is in monitoring mode only
**Action**: Change `p=none` to `p=quarantine` after reviewing reports
**Impact**: Active protection against email spoofing

#### "Consider implementing DKIM signing"
**Meaning**: No valid DKIM records found
**Action**: Configure DKIM with your email provider or server
**Impact**: Improved email deliverability and authentication

#### "Domain found on spam blacklists"
**Meaning**: Domain reputation issues detected
**Action**: Review email practices and request delisting
**Impact**: Email deliverability problems

## Troubleshooting

### "No SPF record found"
- Verify domain spelling
- Check DNS propagation (use `dig TXT example.com`)
- SPF records must be TXT records, not SPF records

### "DNS query failed"
- Check network connectivity
- Verify domain exists and is properly configured
- Try with `--verbose` for detailed error information

### "Invalid DMARC record"
- DMARC records must be at `_dmarc.domain.com`
- Must start with `v=DMARC1`
- Check syntax against DMARC specification

### "No DKIM records found"
- DKIM selectors must be explicitly configured
- Tool checks common selectors but may miss custom ones
- Verify DKIM is enabled with your email provider

## Best Practices

### Email Security Implementation Order

1. **SPF First**: Start with `v=spf1 ~all` for monitoring
2. **DKIM Setup**: Configure DKIM signing
3. **DMARC Monitoring**: Add `p=none` with reporting
4. **Gradual Enforcement**: Move to `p=quarantine` then `p=reject`
5. **Advanced Features**: Add MTA-STS, TLS-RPT, BIMI

### Regular Monitoring

- Run analysis monthly to check for configuration drift
- Monitor DMARC reports for legitimate email failures
- Review threat intelligence for reputation changes
- Update security policies based on recommendations

### Documentation

- Document all email security configurations
- Keep track of email providers and authorized senders
- Maintain contact information for security reports
- Document incident response procedures for email security issues

## Integration Examples

### Bash Script for Regular Monitoring
```bash
#!/bin/bash
DOMAIN="yourdomain.com"
OUTPUT_FILE="email-security-$(date +%Y%m%d).json"

python lookup.py $DOMAIN --format json --output $OUTPUT_FILE

# Check for critical issues
if grep -q '"level": "dangerous"' $OUTPUT_FILE; then
    echo "CRITICAL: Dangerous email security configuration detected!"
    # Send alert notification
fi
```

### Python Integration
```python
import subprocess
import json

def analyze_domain(domain):
    """Analyze domain email security and return results."""
    result = subprocess.run([
        'python', 'lookup.py', domain, 
        '--format', 'json', '--minimal'
    ], capture_output=True, text=True)
    
    if result.returncode == 0:
        return json.loads(result.stdout)
    else:
        raise Exception(f"Analysis failed: {result.stderr}")

# Usage
results = analyze_domain("example.com")
spf_status = results['spf']['present']
dmarc_policy = results['dmarc']['level']
```

This comprehensive usage guide should help users understand and effectively utilize the SPF Lookup Tool for email security analysis and improvement.