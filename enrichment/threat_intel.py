"""
Threat intelligence integration for domain reputation and security context.
"""
import requests
import dns.resolver
from typing import Dict, List, Optional, Any
import logging
from urllib.parse import urljoin

logger = logging.getLogger(__name__)


class ThreatIntelligence:
    """Provides threat intelligence context for domains."""
    
    def __init__(self, timeout: float = 10.0):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.timeout = timeout
        self.session.headers.update({
            'User-Agent': 'SPF-Lookup-Tool/1.0'
        })
        
        # Common spam blacklists (DNS-based)
        self.dns_blacklists = [
            'zen.spamhaus.org',
            'bl.spamcop.net',
            'dnsbl.sorbs.net',
            'b.barracudacentral.org',
            'dnsbl.inps.de',
            'bl.emailbasura.org',
            'combined.njabl.org'
        ]
    
    def check_domain_reputation(self, domain: str) -> Dict[str, Any]:
        """Check domain reputation across multiple sources."""
        reputation = {
            'domain': domain,
            'overall_status': 'unknown',
            'checks': {
                'blacklist_status': self._check_dns_blacklists(domain),
                'domain_age': self._estimate_domain_age(domain),
                'mx_reputation': self._check_mx_reputation(domain)
            },
            'warnings': [],
            'security_notes': []
        }
        
        # Aggregate overall status
        self._determine_overall_reputation(reputation)
        
        return reputation
    
    def _check_dns_blacklists(self, domain: str) -> Dict[str, Any]:
        """Check domain against DNS-based blacklists."""
        blacklist_results = {
            'listed_on': [],
            'total_checked': len(self.dns_blacklists),
            'status': 'clean'
        }
        
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 5
        
        for blacklist in self.dns_blacklists:
            try:
                query = f"{domain}.{blacklist}"
                answers = resolver.resolve(query, 'A')
                
                # If we get a response, domain is listed
                if answers:
                    blacklist_results['listed_on'].append({
                        'blacklist': blacklist,
                        'response': str(answers[0])
                    })
            
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                # NXDOMAIN or NoAnswer means not listed (good)
                continue
            except Exception as e:
                logger.debug(f"Blacklist check failed for {blacklist}: {e}")
                continue
        
        if blacklist_results['listed_on']:
            blacklist_results['status'] = 'blacklisted'
        
        return blacklist_results
    
    def _estimate_domain_age(self, domain: str) -> Dict[str, Any]:
        """Attempt to estimate domain age and registration info."""
        domain_info = {
            'estimated_age': 'unknown',
            'status': 'unknown',
            'notes': []
        }
        
        # For now, we'll use basic heuristics
        # In a production system, you'd integrate with WHOIS services
        
        # Check if domain looks like a subdomain
        parts = domain.split('.')
        if len(parts) > 2:
            domain_info['notes'].append('Subdomain detected - inherits parent domain reputation')
        
        # Check for suspicious patterns
        if any(char.isdigit() for char in domain.replace('.', '')):
            if sum(char.isdigit() for char in domain.replace('.', '')) > len(domain) * 0.3:
                domain_info['notes'].append('High number of digits in domain name')
        
        # Check for very long domains
        if len(domain.replace('.', '')) > 30:
            domain_info['notes'].append('Unusually long domain name')
        
        return domain_info
    
    def _check_mx_reputation(self, domain: str) -> Dict[str, Any]:
        """Check MX record reputation and configuration."""
        mx_info = {
            'mx_records': [],
            'providers': [],
            'status': 'unknown',
            'notes': []
        }
        
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = self.timeout
            answers = resolver.resolve(domain, 'MX')
            
            for rdata in answers:
                mx_host = str(rdata.exchange).rstrip('.')
                mx_info['mx_records'].append({
                    'priority': rdata.preference,
                    'exchange': mx_host
                })
                
                # Identify common email providers
                provider = self._identify_email_provider(mx_host)
                if provider and provider not in mx_info['providers']:
                    mx_info['providers'].append(provider)
            
            if mx_info['mx_records']:
                mx_info['status'] = 'configured'
            
            # Check for potential issues
            if len(mx_info['mx_records']) == 1:
                mx_info['notes'].append('Single MX record - consider adding backup MX for redundancy')
            
        except Exception as e:
            logger.debug(f"MX lookup failed for {domain}: {e}")
            mx_info['status'] = 'error'
            mx_info['notes'].append('Could not retrieve MX records')
        
        return mx_info
    
    def _identify_email_provider(self, mx_host: str) -> Optional[str]:
        """Identify email service provider based on MX hostname."""
        mx_host = mx_host.lower()
        
        providers = {
            'google': ['gmail.com', 'googlemail.com', 'google.com'],
            'microsoft': ['outlook.com', 'hotmail.com', 'live.com', 'office365.com'],
            'amazon': ['amazonses.com'],
            'mailgun': ['mailgun.org'],
            'sendgrid': ['sendgrid.net'],
            'proofpoint': ['pphosted.com', 'proofpoint.com'],
            'mimecast': ['mimecast.com'],
            'cloudflare': ['cloudflare.com'],
            'fastmail': ['fastmail.com']
        }
        
        for provider, domains in providers.items():
            if any(domain in mx_host for domain in domains):
                return provider
        
        return None
    
    def _determine_overall_reputation(self, reputation: Dict[str, Any]) -> None:
        """Determine overall reputation status based on all checks."""
        blacklist_status = reputation['checks']['blacklist_status']['status']
        
        if blacklist_status == 'blacklisted':
            reputation['overall_status'] = 'suspicious'
            reputation['warnings'].append('Domain found on spam blacklists')
        else:
            reputation['overall_status'] = 'clean'
        
        # Add security notes based on findings
        mx_providers = reputation['checks']['mx_reputation'].get('providers', [])
        if mx_providers:
            reputation['security_notes'].append(f'Email providers: {", ".join(mx_providers)}')
        
        domain_notes = reputation['checks']['domain_age'].get('notes', [])
        for note in domain_notes:
            reputation['security_notes'].append(note)
    
    def analyze_subdomain_security(self, domain: str) -> Dict[str, Any]:
        """Analyze subdomain email security inheritance."""
        analysis = {
            'domain': domain,
            'is_subdomain': False,
            'parent_domain': None,
            'security_inheritance': {},
            'recommendations': []
        }
        
        # Check if this is a subdomain
        parts = domain.split('.')
        if len(parts) > 2:
            analysis['is_subdomain'] = True
            # Assume last two parts are the parent domain for most TLDs
            analysis['parent_domain'] = '.'.join(parts[-2:])
            
            analysis['recommendations'].append(
                'Subdomain detected - verify email security policies are properly inherited or explicitly configured'
            )
            
            # Note about DMARC inheritance
            analysis['security_inheritance']['dmarc'] = (
                'DMARC policies are inherited from parent domain if not explicitly set'
            )
            
            analysis['security_inheritance']['spf'] = (
                'SPF records must be explicitly configured for subdomains'
            )
            
            analysis['security_inheritance']['dkim'] = (
                'DKIM records must be explicitly configured for subdomains'
            )
        
        return analysis
    
    def get_security_recommendations(self, domain: str, email_security_status: Dict[str, Any]) -> List[str]:
        """Generate security recommendations based on domain analysis."""
        recommendations = []
        
        # Check reputation issues
        reputation = self.check_domain_reputation(domain)
        if reputation['overall_status'] == 'suspicious':
            recommendations.append(
                'Domain has reputation issues - monitor email delivery and consider remediation'
            )
        
        # Check for subdomain specific recommendations
        subdomain_analysis = self.analyze_subdomain_security(domain)
        recommendations.extend(subdomain_analysis.get('recommendations', []))
        
        # Email provider specific recommendations
        mx_providers = reputation['checks']['mx_reputation'].get('providers', [])
        
        if 'google' in mx_providers:
            recommendations.append(
                'Using Google Workspace - ensure DKIM signing is enabled in admin console'
            )
        
        if 'microsoft' in mx_providers:
            recommendations.append(
                'Using Microsoft 365 - verify DKIM signing is enabled and SPF includes Office365 IPs'
            )
        
        if not mx_providers or 'unknown' in str(mx_providers):
            recommendations.append(
                'Custom email infrastructure detected - ensure proper security monitoring and maintenance'
            )
        
        return recommendations