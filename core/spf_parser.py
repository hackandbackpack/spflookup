"""
SPF record parser and analyzer.
"""
import re
from typing import Dict, List, Optional, Any, Tuple
import logging

logger = logging.getLogger(__name__)


class SPFParser:
    """Parses and analyzes SPF records."""
    
    # SPF mechanisms and their patterns
    SPF_MECHANISMS = {
        'all': r'([+\-~?]?)all',
        'include': r'include:([^\s]+)',
        'a': r'a(?::([^\s/]+))?(?:/(\d+))?',
        'mx': r'mx(?::([^\s/]+))?(?:/(\d+))?',
        'ptr': r'ptr(?::([^\s]+))?',
        'ip4': r'ip4:([^\s/]+)(?:/(\d+))?',
        'ip6': r'ip6:([^\s/]+)(?:/(\d+))?',
        'exists': r'exists:([^\s]+)',
        'redirect': r'redirect=([^\s]+)'
    }
    
    def __init__(self):
        self.dns_lookups = 0
        self.max_dns_lookups = 10
        self.include_chain = []
    
    def parse_spf_record(self, spf_record: str) -> Dict[str, Any]:
        """Parse an SPF record and extract all mechanisms and modifiers."""
        if not spf_record:
            return {'valid': False, 'error': 'No SPF record found'}
        
        # Reset counters for new parsing
        self.dns_lookups = 0
        self.include_chain = []
        
        # Basic validation
        if not spf_record.lower().startswith('v=spf1'):
            return {'valid': False, 'error': 'Invalid SPF record - must start with v=spf1'}
        
        result = {
            'valid': True,
            'version': 'spf1',
            'mechanisms': [],
            'modifiers': {},
            'dns_lookups': 0,
            'warnings': [],
            'errors': []
        }
        
        # Split record into terms (mechanisms and modifiers)
        terms = spf_record.split()[1:]  # Skip v=spf1
        
        for term in terms:
            term = term.strip()
            if not term:
                continue
                
            self._parse_term(term, result)
        
        # Post-processing validation
        self._validate_spf_record(result)
        
        return result
    
    def _parse_term(self, term: str, result: Dict[str, Any]) -> None:
        """Parse a single SPF term (mechanism or modifier)."""
        
        # Check if it's a modifier (contains =)
        if '=' in term and not term.startswith(('include:', 'redirect=')):
            self._parse_modifier(term, result)
            return
        
        # Parse mechanisms
        for mechanism_name, pattern in self.SPF_MECHANISMS.items():
            match = re.match(pattern, term, re.IGNORECASE)
            if match:
                self._parse_mechanism(mechanism_name, match, result)
                return
        
        # Unknown term
        result['warnings'].append(f'Unknown SPF term: {term}')
    
    def _parse_mechanism(self, mechanism_name: str, match: re.Match, result: Dict[str, Any]) -> None:
        """Parse a specific SPF mechanism."""
        groups = match.groups()
        
        mechanism = {
            'type': mechanism_name,
            'qualifier': groups[0] if groups and groups[0] else '+',
            'raw': match.group(0)
        }
        
        if mechanism_name == 'all':
            mechanism['qualifier'] = groups[0] if groups[0] else '+'
        
        elif mechanism_name == 'include':
            mechanism['domain'] = groups[0]
            self.dns_lookups += 1
            self.include_chain.append(groups[0])
        
        elif mechanism_name in ['a', 'mx']:
            if groups[0]:  # domain specified
                mechanism['domain'] = groups[0]
            if groups[1]:  # CIDR specified
                mechanism['cidr'] = int(groups[1])
            self.dns_lookups += 1
        
        elif mechanism_name == 'ptr':
            if groups[0]:
                mechanism['domain'] = groups[0]
            self.dns_lookups += 1
        
        elif mechanism_name in ['ip4', 'ip6']:
            mechanism['ip'] = groups[0]
            if groups[1]:
                mechanism['cidr'] = int(groups[1])
        
        elif mechanism_name == 'exists':
            mechanism['domain'] = groups[0]
            self.dns_lookups += 1
        
        elif mechanism_name == 'redirect':
            mechanism['domain'] = groups[0]
            self.dns_lookups += 1
        
        result['mechanisms'].append(mechanism)
    
    def _parse_modifier(self, term: str, result: Dict[str, Any]) -> None:
        """Parse SPF modifiers."""
        try:
            name, value = term.split('=', 1)
            result['modifiers'][name] = value
            
            # Some modifiers cause DNS lookups
            if name in ['redirect', 'exp']:
                self.dns_lookups += 1
                
        except ValueError:
            result['warnings'].append(f'Malformed modifier: {term}')
    
    def _validate_spf_record(self, result: Dict[str, Any]) -> None:
        """Perform validation checks on parsed SPF record."""
        result['dns_lookups'] = self.dns_lookups
        
        # Check DNS lookup limit
        if self.dns_lookups > self.max_dns_lookups:
            result['errors'].append(
                f'Too many DNS lookups ({self.dns_lookups} > {self.max_dns_lookups}). '
                'This will cause SPF evaluation to fail with PermError.'
            )
        
        # Check for multiple 'all' mechanisms
        all_mechanisms = [m for m in result['mechanisms'] if m['type'] == 'all']
        if len(all_mechanisms) > 1:
            result['warnings'].append('Multiple "all" mechanisms found - only the first will be evaluated')
        
        # Check 'all' mechanism qualifier
        if all_mechanisms:
            all_mechanism = all_mechanisms[0]
            if all_mechanism['qualifier'] == '+':
                result['warnings'].append(
                    'SPF record uses "+all" which allows all senders. This is dangerous!'
                )
            elif all_mechanism['qualifier'] == '?':
                result['warnings'].append(
                    'SPF record uses "?all" (neutral). Consider using "~all" or "-all" for better protection.'
                )
        else:
            result['warnings'].append('No "all" mechanism found - SPF record may be incomplete')
        
        # Check for very long include chains
        if len(self.include_chain) > 5:
            result['warnings'].append(
                f'Long include chain detected ({len(self.include_chain)} includes). '
                'This increases DNS lookup overhead.'
            )
    
    def analyze_spf_strength(self, parsed_spf: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze the strength and security of an SPF record."""
        if not parsed_spf.get('valid'):
            return {
                'level': 'none',
                'description': 'No valid SPF record',
                'recommendations': ['Implement a proper SPF record']
            }
        
        analysis = {
            'level': 'unknown',
            'description': '',
            'recommendations': [],
            'security_issues': [],
            'strengths': []
        }
        
        # Check 'all' mechanism
        all_mechanisms = [m for m in parsed_spf['mechanisms'] if m['type'] == 'all']
        if all_mechanisms:
            qualifier = all_mechanisms[0]['qualifier']
            
            if qualifier == '-':
                analysis['level'] = 'strict'
                analysis['description'] = 'Strict SPF policy (hard fail)'
                analysis['strengths'].append('Uses "-all" for strict enforcement')
            elif qualifier == '~':
                analysis['level'] = 'moderate'
                analysis['description'] = 'Moderate SPF policy (soft fail)'
                analysis['strengths'].append('Uses "~all" for soft enforcement')
            elif qualifier == '?':
                analysis['level'] = 'permissive'
                analysis['description'] = 'Permissive SPF policy (neutral)'
                analysis['recommendations'].append('Consider changing "?all" to "~all" or "-all"')
            elif qualifier == '+':
                analysis['level'] = 'dangerous'
                analysis['description'] = 'Dangerous SPF policy (allows all)'
                analysis['security_issues'].append('Uses "+all" which defeats SPF protection')
        else:
            analysis['level'] = 'incomplete'
            analysis['description'] = 'Incomplete SPF record (no "all" mechanism)'
            analysis['recommendations'].append('Add an "all" mechanism (preferably "~all" or "-all")')
        
        # Check for common issues
        if parsed_spf.get('dns_lookups', 0) > 8:
            analysis['security_issues'].append('High number of DNS lookups may cause failures')
        
        if len([m for m in parsed_spf['mechanisms'] if m['type'] == 'include']) > 3:
            analysis['recommendations'].append('Consider flattening include chains to reduce DNS lookups')
        
        # Check for IP mechanisms
        ip_mechanisms = [m for m in parsed_spf['mechanisms'] if m['type'] in ['ip4', 'ip6']]
        if ip_mechanisms:
            analysis['strengths'].append(f'Explicitly authorizes {len(ip_mechanisms)} IP ranges')
        
        return analysis