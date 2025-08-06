"""
DMARC policy parser and analyzer.
"""
import re
from typing import Dict, List, Optional, Any
import logging

logger = logging.getLogger(__name__)


class DMARCParser:
    """Parses and analyzes DMARC records."""
    
    def __init__(self):
        self.valid_tags = {
            'v', 'p', 'sp', 'adkim', 'aspf', 'fo', 'pct', 'rf', 'ri', 'rua', 'ruf'
        }
        self.required_tags = {'v', 'p'}
    
    def parse_dmarc_record(self, dmarc_record: str) -> Dict[str, Any]:
        """Parse a DMARC record and extract all tags and values."""
        if not dmarc_record:
            return {'valid': False, 'error': 'No DMARC record found'}
        
        # Remove quotes and extra whitespace
        dmarc_record = dmarc_record.strip().strip('"')
        
        # Basic validation
        if not dmarc_record.lower().startswith('v=dmarc1'):
            return {'valid': False, 'error': 'Invalid DMARC record - must start with v=DMARC1'}
        
        result = {
            'valid': True,
            'version': 'DMARC1',
            'tags': {},
            'warnings': [],
            'errors': []
        }
        
        # Parse tags
        tags = self._parse_tags(dmarc_record)
        
        # Validate and process each tag
        for tag, value in tags.items():
            self._process_tag(tag, value, result)
        
        # Validate required tags
        self._validate_required_tags(result)
        
        # Additional validation
        self._validate_dmarc_policy(result)
        
        return result
    
    def _parse_tags(self, record: str) -> Dict[str, str]:
        """Parse DMARC record into tag-value pairs."""
        tags = {}
        
        # Split by semicolon and process each tag=value pair
        for pair in record.split(';'):
            pair = pair.strip()
            if not pair:
                continue
            
            if '=' in pair:
                tag, value = pair.split('=', 1)
                tags[tag.strip().lower()] = value.strip()
        
        return tags
    
    def _process_tag(self, tag: str, value: str, result: Dict[str, Any]) -> None:
        """Process and validate a single DMARC tag."""
        
        if tag not in self.valid_tags:
            result['warnings'].append(f'Unknown DMARC tag: {tag}')
            result['tags'][tag] = value
            return
        
        # Process specific tags
        if tag == 'v':
            if value.upper() != 'DMARC1':
                result['errors'].append(f'Invalid DMARC version: {value}')
            result['tags'][tag] = value.upper()
        
        elif tag == 'p':
            if value.lower() not in ['none', 'quarantine', 'reject']:
                result['errors'].append(f'Invalid DMARC policy: {value}')
            result['tags'][tag] = value.lower()
        
        elif tag == 'sp':
            if value.lower() not in ['none', 'quarantine', 'reject']:
                result['errors'].append(f'Invalid DMARC subdomain policy: {value}')
            result['tags'][tag] = value.lower()
        
        elif tag in ['adkim', 'aspf']:
            if value.lower() not in ['r', 's']:
                result['errors'].append(f'Invalid {tag.upper()} alignment: {value}')
            result['tags'][tag] = value.lower()
        
        elif tag == 'fo':
            # Failure reporting options
            valid_options = {'0', '1', 'd', 's'}
            fo_values = [v.strip() for v in value.split(':')]
            invalid_values = [v for v in fo_values if v not in valid_options]
            if invalid_values:
                result['errors'].append(f'Invalid fo values: {invalid_values}')
            result['tags'][tag] = value
        
        elif tag == 'pct':
            try:
                pct_value = int(value)
                if not 0 <= pct_value <= 100:
                    result['errors'].append(f'Invalid pct value: {value} (must be 0-100)')
                result['tags'][tag] = pct_value
            except ValueError:
                result['errors'].append(f'Invalid pct value: {value} (must be integer)')
        
        elif tag == 'rf':
            # Report format
            valid_formats = {'afrf', 'iodef'}
            if value.lower() not in valid_formats:
                result['errors'].append(f'Invalid report format: {value}')
            result['tags'][tag] = value.lower()
        
        elif tag == 'ri':
            # Report interval
            try:
                ri_value = int(value)
                if ri_value < 0:
                    result['errors'].append(f'Invalid ri value: {value} (must be non-negative)')
                result['tags'][tag] = ri_value
            except ValueError:
                result['errors'].append(f'Invalid ri value: {value} (must be integer)')
        
        elif tag in ['rua', 'ruf']:
            # Report URIs - validate basic mailto format
            uris = [uri.strip() for uri in value.split(',')]
            valid_uris = []
            for uri in uris:
                if self._validate_report_uri(uri):
                    valid_uris.append(uri)
                else:
                    result['warnings'].append(f'Invalid {tag.upper()} URI: {uri}')
            result['tags'][tag] = valid_uris if valid_uris else value
        
        else:
            result['tags'][tag] = value
    
    def _validate_report_uri(self, uri: str) -> bool:
        """Validate a DMARC report URI."""
        # Basic mailto validation
        if uri.startswith('mailto:'):
            email_part = uri[7:]  # Remove 'mailto:'
            # Very basic email validation
            return '@' in email_part and '.' in email_part.split('@')[1]
        
        # For non-mailto URIs, do basic URL validation
        return uri.startswith(('http://', 'https://'))
    
    def _validate_required_tags(self, result: Dict[str, Any]) -> None:
        """Validate that all required DMARC tags are present."""
        missing_tags = self.required_tags - set(result['tags'].keys())
        if missing_tags:
            result['errors'].append(f'Missing required DMARC tags: {missing_tags}')
            result['valid'] = False
    
    def _validate_dmarc_policy(self, result: Dict[str, Any]) -> None:
        """Perform additional DMARC policy validation."""
        tags = result['tags']
        
        # Check for reporting configuration
        if 'rua' not in tags and 'ruf' not in tags:
            result['warnings'].append(
                'No reporting addresses configured (rua/ruf). '
                'Consider adding aggregate reporting to monitor DMARC effectiveness.'
            )
        
        # Check percentage tag with strict policies
        if tags.get('p') in ['quarantine', 'reject'] and 'pct' in tags:
            pct = tags['pct']
            if pct < 100:
                result['warnings'].append(
                    f'Policy "{tags["p"]}" with pct={pct}% - not all messages will be affected'
                )
        
        # Check subdomain policy
        if 'sp' not in tags and tags.get('p') == 'none':
            result['warnings'].append(
                'Main domain policy is "none" but no subdomain policy specified. '
                'Subdomains inherit the lenient policy.'
            )
    
    def analyze_dmarc_strength(self, parsed_dmarc: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze the strength and security of a DMARC policy."""
        if not parsed_dmarc.get('valid'):
            return {
                'level': 'none',
                'description': 'No valid DMARC policy',
                'recommendations': ['Implement a DMARC policy starting with p=none for monitoring'],
                'security_issues': ['Domain is vulnerable to email spoofing'],
                'strengths': []
            }
        
        tags = parsed_dmarc['tags']
        policy = tags.get('p', 'none')
        
        analysis = {
            'level': policy,
            'description': f'DMARC policy: {policy}',
            'recommendations': [],
            'security_issues': [],
            'strengths': []
        }
        
        # Analyze main policy
        if policy == 'reject':
            analysis['level'] = 'strict'
            analysis['description'] = 'Strict DMARC policy (reject)'
            analysis['strengths'].append('Uses strongest DMARC policy (reject)')
        elif policy == 'quarantine':
            analysis['level'] = 'moderate'
            analysis['description'] = 'Moderate DMARC policy (quarantine)'
            analysis['strengths'].append('Uses moderate DMARC protection')
            analysis['recommendations'].append('Consider upgrading to p=reject for maximum protection')
        elif policy == 'none':
            analysis['level'] = 'monitoring'
            analysis['description'] = 'DMARC monitoring only (no enforcement)'
            analysis['recommendations'].append('Upgrade to p=quarantine or p=reject for active protection')
        
        # Check percentage
        pct = tags.get('pct', 100)
        if pct < 100 and policy in ['quarantine', 'reject']:
            analysis['security_issues'].append(f'Only {pct}% of messages affected by policy')
            analysis['recommendations'].append('Increase pct to 100 for full protection')
        
        # Check alignment
        aspf = tags.get('aspf', 'r')
        adkim = tags.get('adkim', 'r')
        
        if aspf == 's':
            analysis['strengths'].append('Strict SPF alignment configured')
        else:
            analysis['recommendations'].append('Consider strict SPF alignment (aspf=s)')
        
        if adkim == 's':
            analysis['strengths'].append('Strict DKIM alignment configured')
        else:
            analysis['recommendations'].append('Consider strict DKIM alignment (adkim=s)')
        
        # Check reporting
        if 'rua' in tags:
            analysis['strengths'].append('Aggregate reporting configured')
        else:
            analysis['recommendations'].append('Configure aggregate reporting (rua) for visibility')
        
        if 'ruf' in tags:
            analysis['strengths'].append('Failure reporting configured')
        
        # Check subdomain policy
        sp = tags.get('sp')
        if sp:
            if sp == policy:
                analysis['strengths'].append('Consistent subdomain policy')
            elif sp in ['quarantine', 'reject'] and policy == 'none':
                analysis['strengths'].append('Subdomain policy stricter than main domain')
            else:
                analysis['recommendations'].append('Review subdomain policy alignment with main policy')
        elif policy == 'none':
            analysis['recommendations'].append('Consider explicit subdomain policy (sp tag)')
        
        return analysis