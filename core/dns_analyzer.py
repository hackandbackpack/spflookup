"""
Core DNS analysis engine for email security records.
"""
import dns.resolver
import dns.exception
from typing import Dict, List, Optional, Any
import logging

logger = logging.getLogger(__name__)


class DNSAnalyzer:
    """Handles DNS queries for email security records."""
    
    def __init__(self, timeout: float = 10.0, retry_count: int = 3):
        self.timeout = timeout
        self.retry_count = retry_count
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout * retry_count
    
    def query_txt_record(self, domain: str, record_type: str = "TXT") -> List[str]:
        """Query TXT records for a domain."""
        try:
            answers = self.resolver.resolve(domain, record_type)
            return [str(rdata).strip('"') for rdata in answers]
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout) as e:
            logger.debug(f"DNS query failed for {domain} ({record_type}): {e}")
            return []
        except Exception as e:
            logger.error(f"Unexpected DNS error for {domain}: {e}")
            return []
    
    def query_mx_record(self, domain: str) -> List[Dict[str, Any]]:
        """Query MX records for a domain."""
        try:
            answers = self.resolver.resolve(domain, 'MX')
            mx_records = []
            for rdata in answers:
                mx_records.append({
                    'priority': rdata.preference,
                    'exchange': str(rdata.exchange).rstrip('.')
                })
            return sorted(mx_records, key=lambda x: x['priority'])
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout) as e:
            logger.debug(f"MX query failed for {domain}: {e}")
            return []
        except Exception as e:
            logger.error(f"Unexpected MX query error for {domain}: {e}")
            return []
    
    def get_spf_record(self, domain: str) -> Optional[str]:
        """Extract SPF record from domain TXT records."""
        txt_records = self.query_txt_record(domain)
        for record in txt_records:
            if record.lower().startswith('v=spf1'):
                return record
        return None
    
    def get_dmarc_record(self, domain: str) -> Optional[str]:
        """Extract DMARC record from _dmarc subdomain."""
        dmarc_domain = f"_dmarc.{domain}"
        txt_records = self.query_txt_record(dmarc_domain)
        for record in txt_records:
            if record.lower().startswith('v=dmarc1'):
                return record
        return None
    
    def get_dkim_record(self, domain: str, selector: str) -> Optional[str]:
        """Extract DKIM record for a specific selector."""
        dkim_domain = f"{selector}._domainkey.{domain}"
        txt_records = self.query_txt_record(dkim_domain)
        for record in txt_records:
            if 'k=' in record.lower() or 'p=' in record.lower():
                return record
        return None
    
    def get_bimi_record(self, domain: str) -> Optional[str]:
        """Extract BIMI record from default._bimi subdomain."""
        bimi_domain = f"default._bimi.{domain}"
        txt_records = self.query_txt_record(bimi_domain)
        for record in txt_records:
            if record.lower().startswith('v=bimi1'):
                return record
        return None
    
    def get_mta_sts_record(self, domain: str) -> Optional[str]:
        """Extract MTA-STS record from _mta-sts subdomain."""
        mta_sts_domain = f"_mta-sts.{domain}"
        txt_records = self.query_txt_record(mta_sts_domain)
        for record in txt_records:
            if record.lower().startswith('v=sts1'):
                return record
        return None
    
    def get_tls_rpt_record(self, domain: str) -> Optional[str]:
        """Extract TLS-RPT record from _smtp._tls subdomain."""
        tls_rpt_domain = f"_smtp._tls.{domain}"
        txt_records = self.query_txt_record(tls_rpt_domain)
        for record in txt_records:
            if record.lower().startswith('v=tlsrpt1'):
                return record
        return None
    
    def discover_dkim_selectors(self, domain: str) -> Dict[str, str]:
        """Attempt to discover DKIM selectors using common names."""
        common_selectors = [
            'default', 'google', 'k1', 's1', 's2', 'dkim', 'mail',
            'selector1', 'selector2', 'amazonses', 'mailgun',
            'mandrill', 'sendgrid', 'mailchimp', 'constantcontact',
            'mimecast', 'proofpoint', 'microsoft', 'office365'
        ]
        
        discovered_selectors = {}
        for selector in common_selectors:
            record = self.get_dkim_record(domain, selector)
            if record:
                discovered_selectors[selector] = record
        
        return discovered_selectors