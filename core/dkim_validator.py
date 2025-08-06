"""
DKIM record validator and analyzer.
"""
import re
import base64
from typing import Dict, List, Optional, Any
import logging
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ed25519
from cryptography.exceptions import InvalidKey

logger = logging.getLogger(__name__)


class DKIMValidator:
    """Validates and analyzes DKIM records."""
    
    def __init__(self):
        self.valid_tags = {
            'v', 'k', 'h', 'p', 'n', 's', 't', 'g'
        }
        self.required_tags = {'p'}  # Public key is required
        self.hash_algorithms = {'sha1', 'sha256'}
        self.key_types = {'rsa', 'ed25519'}
    
    def parse_dkim_record(self, dkim_record: str, selector: str) -> Dict[str, Any]:
        """Parse a DKIM record and extract all tags and values."""
        if not dkim_record:
            return {
                'valid': False, 
                'error': f'No DKIM record found for selector: {selector}',
                'selector': selector
            }
        
        # Clean up the record
        dkim_record = dkim_record.strip().strip('"')
        
        result = {
            'valid': True,
            'selector': selector,
            'tags': {},
            'warnings': [],
            'errors': [],
            'key_info': {}
        }
        
        # Parse tags
        tags = self._parse_tags(dkim_record)
        
        # Process each tag
        for tag, value in tags.items():
            self._process_tag(tag, value, result)
        
        # Validate required tags
        self._validate_required_tags(result)
        
        # Analyze the public key
        if result['valid'] and 'p' in result['tags']:
            self._analyze_public_key(result)
        
        return result
    
    def _parse_tags(self, record: str) -> Dict[str, str]:
        """Parse DKIM record into tag=value pairs."""
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
        """Process and validate a single DKIM tag."""
        
        if tag not in self.valid_tags:
            result['warnings'].append(f'Unknown DKIM tag: {tag}')
            result['tags'][tag] = value
            return
        
        # Process specific tags
        if tag == 'v':
            # Version (usually omitted, defaults to DKIM1)
            if value.upper() != 'DKIM1':
                result['warnings'].append(f'Unusual DKIM version: {value}')
            result['tags'][tag] = value.upper()
        
        elif tag == 'k':
            # Key type
            if value.lower() not in self.key_types:
                result['errors'].append(f'Unsupported key type: {value}')
            result['tags'][tag] = value.lower()
        
        elif tag == 'h':
            # Hash algorithms
            algorithms = [alg.strip().lower() for alg in value.split(':')]
            unsupported = [alg for alg in algorithms if alg not in self.hash_algorithms]
            if unsupported:
                result['warnings'].append(f'Unsupported hash algorithms: {unsupported}')
            result['tags'][tag] = algorithms
        
        elif tag == 'p':
            # Public key
            if not value:
                result['errors'].append('Empty public key - DKIM selector revoked')
                result['valid'] = False
            else:
                # Remove whitespace from key
                clean_key = ''.join(value.split())
                result['tags'][tag] = clean_key
        
        elif tag == 'n':
            # Notes
            result['tags'][tag] = value
        
        elif tag == 's':
            # Service type
            service_types = [svc.strip().lower() for svc in value.split(':')]
            if 'email' not in service_types and '*' not in service_types:
                result['warnings'].append('DKIM key not intended for email service')
            result['tags'][tag] = service_types
        
        elif tag == 't':
            # Flags
            flags = [flag.strip().lower() for flag in value.split(':')]
            valid_flags = {'y', 's'}
            invalid_flags = [flag for flag in flags if flag not in valid_flags]
            if invalid_flags:
                result['warnings'].append(f'Unknown DKIM flags: {invalid_flags}')
            result['tags'][tag] = flags
            
            # Check for testing flag
            if 'y' in flags:
                result['warnings'].append('DKIM key is in testing mode (t=y)')
        
        elif tag == 'g':
            # Granularity (deprecated)
            result['warnings'].append('Granularity tag (g) is deprecated')
            result['tags'][tag] = value
        
        else:
            result['tags'][tag] = value
    
    def _validate_required_tags(self, result: Dict[str, Any]) -> None:
        """Validate that all required DKIM tags are present."""
        missing_tags = self.required_tags - set(result['tags'].keys())
        if missing_tags:
            result['errors'].append(f'Missing required DKIM tags: {missing_tags}')
            result['valid'] = False
    
    def _analyze_public_key(self, result: Dict[str, Any]) -> None:
        """Analyze the DKIM public key."""
        public_key_b64 = result['tags'].get('p', '')
        key_type = result['tags'].get('k', 'rsa').lower()
        
        if not public_key_b64:
            return
        
        try:
            # Decode base64 key
            public_key_der = base64.b64decode(public_key_b64)
            
            # Analyze based on key type
            if key_type == 'rsa':
                self._analyze_rsa_key(public_key_der, result)
            elif key_type == 'ed25519':
                self._analyze_ed25519_key(public_key_der, result)
            else:
                result['warnings'].append(f'Unable to analyze {key_type} key')
        
        except Exception as e:
            result['errors'].append(f'Failed to parse public key: {str(e)}')
    
    def _analyze_rsa_key(self, key_der: bytes, result: Dict[str, Any]) -> None:
        """Analyze RSA public key."""
        try:
            public_key = serialization.load_der_public_key(key_der)
            
            if isinstance(public_key, rsa.RSAPublicKey):
                key_size = public_key.key_size
                result['key_info'] = {
                    'type': 'RSA',
                    'size': key_size,
                    'size_bits': key_size
                }
                
                # Check key size security
                if key_size < 1024:
                    result['errors'].append(f'RSA key size {key_size} bits is dangerously weak')
                elif key_size < 2048:
                    result['warnings'].append(f'RSA key size {key_size} bits is weak, recommend 2048+ bits')
                elif key_size >= 2048:
                    result['key_info']['strength'] = 'adequate' if key_size == 2048 else 'strong'
            else:
                result['warnings'].append('Public key is not RSA despite k=rsa tag')
        
        except Exception as e:
            result['errors'].append(f'Failed to analyze RSA key: {str(e)}')
    
    def _analyze_ed25519_key(self, key_der: bytes, result: Dict[str, Any]) -> None:
        """Analyze Ed25519 public key."""
        try:
            public_key = serialization.load_der_public_key(key_der)
            
            if isinstance(public_key, ed25519.Ed25519PublicKey):
                result['key_info'] = {
                    'type': 'Ed25519',
                    'size': 256,  # Ed25519 keys are always 256 bits
                    'size_bits': 256,
                    'strength': 'strong'
                }
            else:
                result['warnings'].append('Public key is not Ed25519 despite k=ed25519 tag')
        
        except Exception as e:
            result['errors'].append(f'Failed to analyze Ed25519 key: {str(e)}')
    
    def analyze_dkim_strength(self, parsed_dkim: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze the strength and security of a DKIM configuration."""
        if not parsed_dkim.get('valid'):
            return {
                'level': 'none',
                'description': f'No valid DKIM record for selector: {parsed_dkim.get("selector", "unknown")}',
                'recommendations': ['Implement DKIM signing for this selector'],
                'security_issues': ['DKIM authentication not available'],
                'strengths': []
            }
        
        analysis = {
            'level': 'unknown',
            'description': 'DKIM record found',
            'recommendations': [],
            'security_issues': [],
            'strengths': []
        }
        
        # Analyze key strength
        key_info = parsed_dkim.get('key_info', {})
        if key_info:
            key_type = key_info.get('type', 'unknown')
            key_size = key_info.get('size', 0)
            
            if key_type == 'RSA':
                if key_size >= 2048:
                    analysis['level'] = 'strong'
                    analysis['description'] = f'Strong DKIM configuration (RSA-{key_size})'
                    analysis['strengths'].append(f'Uses {key_size}-bit RSA key')
                elif key_size >= 1024:
                    analysis['level'] = 'moderate'
                    analysis['description'] = f'Moderate DKIM configuration (RSA-{key_size})'
                    analysis['recommendations'].append('Upgrade to 2048-bit RSA key or Ed25519')
                else:
                    analysis['level'] = 'weak'
                    analysis['description'] = f'Weak DKIM configuration (RSA-{key_size})'
                    analysis['security_issues'].append('Key size is cryptographically weak')
            
            elif key_type == 'Ed25519':
                analysis['level'] = 'strong'
                analysis['description'] = 'Strong DKIM configuration (Ed25519)'
                analysis['strengths'].append('Uses modern Ed25519 cryptography')
        
        # Check hash algorithms
        hash_algs = parsed_dkim['tags'].get('h', ['sha256'])  # Default to sha256
        if isinstance(hash_algs, str):
            hash_algs = [hash_algs]
        
        if 'sha1' in hash_algs and 'sha256' not in hash_algs:
            analysis['security_issues'].append('Only supports SHA-1 hashing (deprecated)')
            analysis['recommendations'].append('Upgrade to support SHA-256 hashing')
        elif 'sha256' in hash_algs:
            analysis['strengths'].append('Supports SHA-256 hashing')
        
        # Check testing mode
        flags = parsed_dkim['tags'].get('t', [])
        if 'y' in flags:
            analysis['recommendations'].append('Remove testing flag (t=y) from production DKIM key')
        
        # Check service restriction
        service_types = parsed_dkim['tags'].get('s', ['*'])
        if 'email' in service_types or '*' in service_types:
            analysis['strengths'].append('Properly configured for email service')
        
        return analysis
    
    def get_common_selectors(self) -> List[str]:
        """Return list of commonly used DKIM selectors."""
        return [
            'default', 'google', 'k1', 's1', 's2', 'dkim', 'mail',
            'selector1', 'selector2', 'amazonses', 'mailgun',
            'mandrill', 'sendgrid', 'mailchimp', 'constantcontact',
            'mimecast', 'proofpoint', 'microsoft', 'office365'
        ]