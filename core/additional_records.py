"""
Parser for additional email security records (BIMI, MTA-STS, TLS-RPT).
"""
import re
import requests
from typing import Dict, List, Optional, Any, Union
import logging
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


class AdditionalRecordsParser:
    """Parses and analyzes additional email security records."""
    
    def __init__(self, timeout: float = 10.0):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.timeout = timeout
    
    def parse_bimi_record(self, bimi_record: str) -> Dict[str, Any]:
        """Parse a BIMI record."""
        if not bimi_record:
            return {'valid': False, 'error': 'No BIMI record found'}
        
        # Clean up the record
        bimi_record = bimi_record.strip().strip('"')
        
        # Basic validation
        if not bimi_record.lower().startswith('v=bimi1'):
            return {'valid': False, 'error': 'Invalid BIMI record - must start with v=BIMI1'}
        
        result = {
            'valid': True,
            'version': 'BIMI1',
            'tags': {},
            'warnings': [],
            'errors': []
        }
        
        # Parse tags
        tags = self._parse_tags(bimi_record)
        
        # Process each tag
        for tag, value in tags.items():
            if tag == 'v':
                if value.upper() != 'BIMI1':
                    result['errors'].append(f'Invalid BIMI version: {value}')
                result['tags'][tag] = value.upper()
            elif tag == 'l':
                # Logo URL
                if self._validate_url(value):
                    result['tags'][tag] = value
                else:
                    result['errors'].append(f'Invalid logo URL: {value}')
            elif tag == 'a':
                # VMC (Verified Mark Certificate) URL
                if self._validate_url(value):
                    result['tags'][tag] = value
                else:
                    result['errors'].append(f'Invalid VMC URL: {value}')
            else:
                result['warnings'].append(f'Unknown BIMI tag: {tag}')
                result['tags'][tag] = value
        
        # Additional validation
        if 'l' not in result['tags']:
            result['warnings'].append('No logo URL specified in BIMI record')
        
        return result
    
    def parse_mta_sts_record(self, mta_sts_record: str) -> Dict[str, Any]:
        """Parse an MTA-STS record."""
        if not mta_sts_record:
            return {'valid': False, 'error': 'No MTA-STS record found'}
        
        # Clean up the record
        mta_sts_record = mta_sts_record.strip().strip('"')
        
        # Basic validation
        if not mta_sts_record.lower().startswith('v=sts1'):
            return {'valid': False, 'error': 'Invalid MTA-STS record - must start with v=STSv1'}
        
        result = {
            'valid': True,
            'version': 'STSv1',
            'tags': {},
            'warnings': [],
            'errors': []
        }
        
        # Parse tags
        tags = self._parse_tags(mta_sts_record)
        
        # Process each tag
        for tag, value in tags.items():
            if tag == 'v':
                if value.upper() not in ['STS1', 'STSV1']:
                    result['errors'].append(f'Invalid MTA-STS version: {value}')
                result['tags'][tag] = value.upper()
            elif tag == 'id':
                # Policy ID
                result['tags'][tag] = value
            else:
                result['warnings'].append(f'Unknown MTA-STS tag: {tag}')
                result['tags'][tag] = value
        
        # Validate required fields
        if 'id' not in result['tags']:
            result['errors'].append('Missing required MTA-STS id tag')
            result['valid'] = False
        
        return result
    
    def parse_tls_rpt_record(self, tls_rpt_record: str) -> Dict[str, Any]:
        """Parse a TLS-RPT record."""
        if not tls_rpt_record:
            return {'valid': False, 'error': 'No TLS-RPT record found'}
        
        # Clean up the record
        tls_rpt_record = tls_rpt_record.strip().strip('"')
        
        # Basic validation
        if not tls_rpt_record.lower().startswith('v=tlsrpt1'):
            return {'valid': False, 'error': 'Invalid TLS-RPT record - must start with v=TLSRPTv1'}
        
        result = {
            'valid': True,
            'version': 'TLSRPTv1',
            'tags': {},
            'warnings': [],
            'errors': []
        }
        
        # Parse tags
        tags = self._parse_tags(tls_rpt_record)
        
        # Process each tag
        for tag, value in tags.items():
            if tag == 'v':
                if value.upper() not in ['TLSRPT1', 'TLSRPTV1']:
                    result['errors'].append(f'Invalid TLS-RPT version: {value}')
                result['tags'][tag] = value.upper()
            elif tag == 'rua':
                # Report URI for aggregate reports
                uris = [uri.strip() for uri in value.split(',')]
                valid_uris = []
                for uri in uris:
                    if self._validate_report_uri(uri):
                        valid_uris.append(uri)
                    else:
                        result['errors'].append(f'Invalid TLS-RPT rua URI: {uri}')
                result['tags'][tag] = valid_uris if valid_uris else value
            else:
                result['warnings'].append(f'Unknown TLS-RPT tag: {tag}')
                result['tags'][tag] = value
        
        # Validate required fields
        if 'rua' not in result['tags']:
            result['errors'].append('Missing required TLS-RPT rua tag')
            result['valid'] = False
        
        return result
    
    def fetch_mta_sts_policy(self, domain: str) -> Dict[str, Any]:
        """Fetch and parse MTA-STS policy from well-known URL."""
        policy_url = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"
        
        try:
            response = self.session.get(policy_url, timeout=self.timeout)
            response.raise_for_status()
            
            policy_text = response.text.strip()
            return self._parse_mta_sts_policy(policy_text)
        
        except requests.RequestException as e:
            logger.debug(f"Failed to fetch MTA-STS policy from {policy_url}: {e}")
            return {
                'valid': False,
                'error': f'Failed to fetch MTA-STS policy: {str(e)}',
                'url': policy_url
            }
    
    def _parse_mta_sts_policy(self, policy_text: str) -> Dict[str, Any]:
        """Parse MTA-STS policy text."""
        result = {
            'valid': True,
            'directives': {},
            'warnings': [],
            'errors': []
        }
        
        required_directives = {'version', 'mode'}
        
        for line in policy_text.split('\n'):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            if ':' in line:
                key, value = line.split(':', 1)
                key = key.strip().lower()
                value = value.strip()
                
                if key == 'version':
                    if value.upper() != 'STSV1':
                        result['errors'].append(f'Invalid MTA-STS policy version: {value}')
                    result['directives'][key] = value.upper()
                elif key == 'mode':
                    if value.lower() not in ['enforce', 'testing', 'none']:
                        result['errors'].append(f'Invalid MTA-STS mode: {value}')
                    result['directives'][key] = value.lower()
                elif key == 'max_age':
                    try:
                        max_age = int(value)
                        if max_age < 0:
                            result['errors'].append('MTA-STS max_age must be non-negative')
                        result['directives'][key] = max_age
                    except ValueError:
                        result['errors'].append(f'Invalid MTA-STS max_age: {value}')
                elif key == 'mx':
                    # Multiple mx entries are allowed
                    if 'mx' not in result['directives']:
                        result['directives']['mx'] = []
                    result['directives']['mx'].append(value)
                else:
                    result['warnings'].append(f'Unknown MTA-STS directive: {key}')
                    result['directives'][key] = value
        
        # Check required directives
        missing_directives = required_directives - set(result['directives'].keys())
        if missing_directives:
            result['errors'].append(f'Missing required MTA-STS directives: {missing_directives}')
            result['valid'] = False
        
        # Validate mode-specific requirements
        mode = result['directives'].get('mode')
        if mode in ['enforce', 'testing'] and 'mx' not in result['directives']:
            result['errors'].append('MTA-STS policy in enforce/testing mode must specify mx hosts')
        
        return result
    
    def _parse_tags(self, record: str) -> Dict[str, str]:
        """Parse record into tag=value pairs."""
        tags = {}
        
        for pair in record.split(';'):
            pair = pair.strip()
            if not pair:
                continue
            
            if '=' in pair:
                tag, value = pair.split('=', 1)
                tags[tag.strip().lower()] = value.strip()
        
        return tags
    
    def _validate_url(self, url: str) -> bool:
        """Validate URL format."""
        try:
            result = urlparse(url)
            return all([result.scheme in ('http', 'https'), result.netloc])
        except Exception:
            return False
    
    def _validate_report_uri(self, uri: str) -> bool:
        """Validate a report URI (mailto or https)."""
        if uri.startswith('mailto:'):
            email_part = uri[7:]
            return '@' in email_part and '.' in email_part.split('@')[1]
        return self._validate_url(uri)
    
    def analyze_additional_records(self, domain: str, records: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze the security implications of additional email security records."""
        analysis = {
            'bimi': {'present': False, 'analysis': {}},
            'mta_sts': {'present': False, 'analysis': {}},
            'tls_rpt': {'present': False, 'analysis': {}},
            'overall_recommendations': []
        }
        
        # Analyze BIMI
        if records.get('bimi'):
            analysis['bimi']['present'] = True
            bimi_record = records['bimi']
            
            if bimi_record.get('valid'):
                analysis['bimi']['analysis'] = {
                    'level': 'implemented',
                    'description': 'BIMI record configured for brand indicators',
                    'strengths': ['Brand logo authentication enabled'],
                    'recommendations': []
                }
                
                if 'a' in bimi_record['tags']:
                    analysis['bimi']['analysis']['strengths'].append('VMC (Verified Mark Certificate) configured')
                else:
                    analysis['bimi']['analysis']['recommendations'].append(
                        'Consider adding VMC for enhanced logo verification'
                    )
            else:
                analysis['bimi']['analysis'] = {
                    'level': 'misconfigured',
                    'description': 'BIMI record found but invalid',
                    'security_issues': [bimi_record.get('error', 'Invalid BIMI record')]
                }
        
        # Analyze MTA-STS
        if records.get('mta_sts'):
            analysis['mta_sts']['present'] = True
            mta_sts_record = records['mta_sts']
            
            if mta_sts_record.get('valid'):
                analysis['mta_sts']['analysis'] = {
                    'level': 'implemented',
                    'description': 'MTA-STS configured for transport security',
                    'strengths': ['Email transport security policy enabled'],
                    'recommendations': []
                }
                
                # Analyze policy if available
                if 'policy' in records and records['policy'].get('valid'):
                    policy = records['policy']
                    mode = policy['directives'].get('mode', 'unknown')
                    
                    if mode == 'enforce':
                        analysis['mta_sts']['analysis']['strengths'].append('Policy in enforce mode')
                    elif mode == 'testing':
                        analysis['mta_sts']['analysis']['recommendations'].append(
                            'Upgrade MTA-STS policy from testing to enforce mode'
                        )
                    elif mode == 'none':
                        analysis['mta_sts']['analysis']['recommendations'].append(
                            'MTA-STS policy disabled - consider enabling'
                        )
            else:
                analysis['mta_sts']['analysis'] = {
                    'level': 'misconfigured',
                    'description': 'MTA-STS record found but invalid',
                    'security_issues': [mta_sts_record.get('error', 'Invalid MTA-STS record')]
                }
        
        # Analyze TLS-RPT
        if records.get('tls_rpt'):
            analysis['tls_rpt']['present'] = True
            tls_rpt_record = records['tls_rpt']
            
            if tls_rpt_record.get('valid'):
                analysis['tls_rpt']['analysis'] = {
                    'level': 'implemented',
                    'description': 'TLS-RPT configured for transport security reporting',
                    'strengths': ['TLS failure reporting enabled'],
                    'recommendations': []
                }
            else:
                analysis['tls_rpt']['analysis'] = {
                    'level': 'misconfigured',
                    'description': 'TLS-RPT record found but invalid',
                    'security_issues': [tls_rpt_record.get('error', 'Invalid TLS-RPT record')]
                }
        
        # Overall recommendations
        if not analysis['mta_sts']['present']:
            analysis['overall_recommendations'].append(
                'Consider implementing MTA-STS for enhanced email transport security'
            )
        
        if not analysis['tls_rpt']['present']:
            analysis['overall_recommendations'].append(
                'Consider implementing TLS-RPT for transport security monitoring'
            )
        
        if not analysis['bimi']['present']:
            analysis['overall_recommendations'].append(
                'Consider implementing BIMI for brand indicator authentication (requires DMARC p=quarantine or p=reject)'
            )
        
        return analysis