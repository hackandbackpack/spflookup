"""
Email security remediation recommendations engine.
"""
from typing import Dict, List, Any
import logging

logger = logging.getLogger(__name__)


class RecommendationsEngine:
    """Generates actionable security recommendations based on email security analysis."""
    
    def generate_recommendations(self, domain: str, analysis_results: Dict[str, Any]) -> List[str]:
        """Generate comprehensive security recommendations."""
        recommendations = []
        
        # SPF recommendations
        spf_recs = self._generate_spf_recommendations(analysis_results.get('spf', {}))
        recommendations.extend(spf_recs)
        
        # DMARC recommendations
        dmarc_recs = self._generate_dmarc_recommendations(analysis_results.get('dmarc', {}))
        recommendations.extend(dmarc_recs)
        
        # DKIM recommendations
        dkim_recs = self._generate_dkim_recommendations(analysis_results.get('dkim', {}))
        recommendations.extend(dkim_recs)
        
        # Additional records recommendations
        additional_recs = self._generate_additional_recommendations(analysis_results.get('additional', {}))
        recommendations.extend(additional_recs)
        
        # Cross-protocol recommendations
        cross_recs = self._generate_cross_protocol_recommendations(analysis_results)
        recommendations.extend(cross_recs)
        
        # Threat intelligence recommendations
        threat_recs = self._generate_threat_intel_recommendations(analysis_results.get('threat_intel', {}))
        recommendations.extend(threat_recs)
        
        # Remove duplicates while preserving order
        seen = set()
        unique_recommendations = []
        for rec in recommendations:
            if rec not in seen:
                seen.add(rec)
                unique_recommendations.append(rec)
        
        return unique_recommendations
    
    def _generate_spf_recommendations(self, spf_data: Dict[str, Any]) -> List[str]:
        """Generate SPF-specific recommendations."""
        recommendations = []
        record_data = spf_data.get('record', {})
        analysis = spf_data.get('analysis', {})
        
        if not record_data.get('valid'):
            recommendations.append("Implement an SPF record to prevent email spoofing. Start with 'v=spf1 ~all' for monitoring.")
            return recommendations
        
        # DNS lookup recommendations
        dns_lookups = record_data.get('dns_lookups', 0)
        if dns_lookups > 8:
            recommendations.append(f"Reduce SPF DNS lookups from {dns_lookups} to under 10 to prevent evaluation failures. Consider SPF flattening.")
        
        # 'all' mechanism recommendations
        mechanisms = record_data.get('mechanisms', [])
        all_mechanisms = [m for m in mechanisms if m.get('type') == 'all']
        
        if not all_mechanisms:
            recommendations.append("Add an 'all' mechanism to your SPF record (preferably '~all' or '-all') to handle unauthorized senders.")
        else:
            all_qualifier = all_mechanisms[0].get('qualifier', '+')
            if all_qualifier == '+':
                recommendations.append("Change '+all' to '~all' or '-all' to prevent SPF bypass. '+all' allows any sender!")
            elif all_qualifier == '?':
                recommendations.append("Upgrade from '?all' to '~all' (soft fail) or '-all' (hard fail) for better email security.")
        
        # Include chain recommendations
        include_mechanisms = [m for m in mechanisms if m.get('type') == 'include']
        if len(include_mechanisms) > 3:
            recommendations.append("Consider consolidating include statements or using SPF flattening to reduce complexity.")
        
        # Analysis-based recommendations
        if analysis.get('level') == 'dangerous':
            recommendations.append("URGENT: Fix dangerous SPF configuration that allows unrestricted email sending.")
        elif analysis.get('level') in ['permissive', 'incomplete']:
            recommendations.append("Strengthen SPF policy by moving from monitoring mode to enforcement with '~all' or '-all'.")
        
        return recommendations
    
    def _generate_dmarc_recommendations(self, dmarc_data: Dict[str, Any]) -> List[str]:
        """Generate DMARC-specific recommendations."""
        recommendations = []
        record_data = dmarc_data.get('record', {})
        analysis = dmarc_data.get('analysis', {})
        
        if not record_data.get('valid'):
            recommendations.append("Implement DMARC policy starting with 'v=DMARC1; p=none; rua=mailto:dmarc@yourdomain.com' for monitoring.")
            return recommendations
        
        tags = record_data.get('tags', {})
        policy = tags.get('p', 'none')
        
        # Policy progression recommendations
        if policy == 'none':
            recommendations.append("Upgrade DMARC policy from 'p=none' to 'p=quarantine' after reviewing reports for legitimate traffic.")
        elif policy == 'quarantine':
            recommendations.append("Consider upgrading to 'p=reject' for maximum email security after ensuring all legitimate email passes DMARC.")
        
        # Reporting recommendations
        if 'rua' not in tags:
            recommendations.append("Add aggregate reporting (rua=mailto:dmarc-reports@yourdomain.com) to monitor DMARC effectiveness.")
        
        if 'ruf' not in tags and policy in ['quarantine', 'reject']:
            recommendations.append("Consider adding failure reporting (ruf) to get detailed information about DMARC failures.")
        
        # Percentage recommendations
        pct = tags.get('pct', 100)
        if pct < 100 and policy in ['quarantine', 'reject']:
            recommendations.append(f"Increase DMARC percentage from {pct}% to 100% for full protection once confident in configuration.")
        
        # Alignment recommendations
        aspf = tags.get('aspf', 'r')
        adkim = tags.get('adkim', 'r')
        
        if aspf == 'r' and policy in ['quarantine', 'reject']:
            recommendations.append("Consider strict SPF alignment (aspf=s) for enhanced security if all legitimate email uses exact domain match.")
        
        if adkim == 'r' and policy in ['quarantine', 'reject']:
            recommendations.append("Consider strict DKIM alignment (adkim=s) for enhanced security if all DKIM signatures use exact domain match.")
        
        # Subdomain policy recommendations
        if 'sp' not in tags and policy == 'none':
            recommendations.append("Consider explicit subdomain policy (sp) to prevent subdomain abuse.")
        
        return recommendations
    
    def _generate_dkim_recommendations(self, dkim_data: Dict[str, Any]) -> List[str]:
        """Generate DKIM-specific recommendations."""
        recommendations = []
        selectors = dkim_data.get('selectors', {})
        
        if not selectors:
            recommendations.append("Implement DKIM signing to authenticate your outgoing emails. Configure at least one DKIM selector.")
            return recommendations
        
        valid_selectors = [s for s, data in selectors.items() if data.get('record', {}).get('valid', False)]
        
        if not valid_selectors:
            recommendations.append("Fix DKIM configuration - found selectors but no valid DKIM records.")
            return recommendations
        
        # Analyze each valid selector
        for selector, selector_data in selectors.items():
            record_data = selector_data.get('record', {})
            analysis = selector_data.get('analysis', {})
            
            if not record_data.get('valid'):
                continue
            
            key_info = record_data.get('key_info', {})
            key_type = key_info.get('type', '')
            key_size = key_info.get('size', 0)
            
            # Key strength recommendations
            if key_type == 'RSA' and key_size < 2048:
                recommendations.append(f"Upgrade DKIM key for selector '{selector}' from {key_size}-bit to 2048-bit RSA or Ed25519 for better security.")
            
            # Testing mode recommendations
            tags = record_data.get('tags', {})
            flags = tags.get('t', [])
            if 'y' in flags:
                recommendations.append(f"Remove testing flag (t=y) from DKIM selector '{selector}' for production use.")
        
        # Multiple selectors recommendations
        if len(valid_selectors) == 1:
            recommendations.append("Consider implementing key rotation by maintaining multiple DKIM selectors.")
        
        return recommendations
    
    def _generate_additional_recommendations(self, additional_data: Dict[str, Any]) -> List[str]:
        """Generate recommendations for additional email security records."""
        recommendations = []
        records = additional_data.get('records', {})
        analysis = additional_data.get('analysis', {})
        
        # BIMI recommendations
        bimi_present = analysis.get('bimi', {}).get('present', False)
        if not bimi_present:
            recommendations.append("Consider implementing BIMI (Brand Indicators for Message Identification) to display your logo in email clients (requires DMARC p=quarantine or p=reject).")
        
        # MTA-STS recommendations
        mta_sts_present = analysis.get('mta_sts', {}).get('present', False)
        if not mta_sts_present:
            recommendations.append("Implement MTA-STS (Mail Transfer Agent Strict Transport Security) to enforce TLS for email delivery and prevent downgrade attacks.")
        else:
            # Check MTA-STS policy mode
            mta_sts_policy = records.get('policy', {})
            if mta_sts_policy.get('valid'):
                mode = mta_sts_policy.get('directives', {}).get('mode', '')
                if mode == 'testing':
                    recommendations.append("Upgrade MTA-STS policy from 'testing' to 'enforce' mode for active protection.")
                elif mode == 'none':
                    recommendations.append("Enable MTA-STS policy by changing mode from 'none' to 'enforce'.")
        
        # TLS-RPT recommendations
        tls_rpt_present = analysis.get('tls_rpt', {}).get('present', False)
        if not tls_rpt_present:
            recommendations.append("Implement TLS-RPT (TLS Reporting) to receive reports about TLS connection failures and monitor email delivery security.")
        
        return recommendations
    
    def _generate_cross_protocol_recommendations(self, analysis_results: Dict[str, Any]) -> List[str]:
        """Generate recommendations that span multiple email security protocols."""
        recommendations = []
        
        # Check for DMARC without SPF/DKIM
        dmarc_valid = analysis_results.get('dmarc', {}).get('record', {}).get('valid', False)
        spf_valid = analysis_results.get('spf', {}).get('record', {}).get('valid', False)
        dkim_selectors = analysis_results.get('dkim', {}).get('selectors', {})
        dkim_valid = any(data.get('record', {}).get('valid', False) for data in dkim_selectors.values())
        
        if dmarc_valid and not spf_valid and not dkim_valid:
            recommendations.append("DMARC policy found but no valid SPF or DKIM records. DMARC requires at least one authentication method (SPF or DKIM) to be effective.")
        
        if dmarc_valid and not spf_valid:
            recommendations.append("Implement SPF record to complement your DMARC policy and provide email authentication redundancy.")
        
        if dmarc_valid and not dkim_valid:
            recommendations.append("Implement DKIM signing to complement your DMARC policy and improve email deliverability.")
        
        # DMARC policy strength vs authentication strength
        dmarc_policy = analysis_results.get('dmarc', {}).get('record', {}).get('tags', {}).get('p', 'none')
        spf_level = analysis_results.get('spf', {}).get('analysis', {}).get('level', 'unknown')
        
        if dmarc_policy in ['quarantine', 'reject'] and spf_level in ['dangerous', 'permissive']:
            recommendations.append("DMARC enforcement policy detected but SPF policy is weak. Strengthen SPF policy to match DMARC enforcement level.")
        
        # BIMI requirements check
        bimi_present = analysis_results.get('additional', {}).get('analysis', {}).get('bimi', {}).get('present', False)
        if bimi_present and dmarc_policy == 'none':
            recommendations.append("BIMI record found but DMARC policy is 'none'. BIMI requires DMARC policy of 'quarantine' or 'reject' to display logos.")
        
        return recommendations
    
    def _generate_threat_intel_recommendations(self, threat_intel: Dict[str, Any]) -> List[str]:
        """Generate recommendations based on threat intelligence."""
        recommendations = []
        
        reputation = threat_intel.get('reputation', {})
        overall_status = reputation.get('overall_status', 'unknown')
        
        if overall_status == 'suspicious':
            recommendations.append("Domain reputation issues detected. Monitor email delivery rates and consider reputation remediation services.")
            
            # Check specific reputation issues
            blacklist = reputation.get('checks', {}).get('blacklist_status', {})
            if blacklist.get('status') == 'blacklisted':
                listed_on = blacklist.get('listed_on', [])
                if listed_on:
                    recommendations.append(f"Domain is blacklisted on {len(listed_on)} spam lists. Review email practices and request delisting from: {', '.join([bl['blacklist'] for bl in listed_on[:3]])}.")
        
        # Subdomain recommendations
        subdomain_analysis = threat_intel.get('subdomain_analysis', {})
        if subdomain_analysis.get('is_subdomain'):
            parent_domain = subdomain_analysis.get('parent_domain')
            if parent_domain:
                recommendations.append(f"Subdomain detected. Ensure email security policies are explicitly configured or properly inherit from parent domain '{parent_domain}'.")
        
        # Email provider recommendations
        mx_info = reputation.get('checks', {}).get('mx_reputation', {})
        providers = mx_info.get('providers', [])
        
        if 'google' in providers:
            recommendations.append("Google Workspace detected. Ensure DKIM is enabled in Google Admin Console and SPF includes Google's servers.")
        elif 'microsoft' in providers:
            recommendations.append("Microsoft 365 detected. Verify DKIM signing is enabled and SPF includes Office 365 IP ranges.")
        elif not providers:
            recommendations.append("Custom email infrastructure detected. Ensure proper security monitoring, logging, and regular security updates.")
        
        return recommendations
    
    def generate_implementation_roadmap(self, analysis_results: Dict[str, Any]) -> Dict[str, List[str]]:
        """Generate a phased implementation roadmap for email security improvements."""
        
        roadmap = {
            "immediate": [],
            "short_term": [],
            "long_term": []
        }
        
        # Immediate actions (security issues that need urgent attention)
        spf_analysis = analysis_results.get('spf', {}).get('analysis', {})
        if spf_analysis.get('level') == 'dangerous':
            roadmap["immediate"].append("Fix dangerous SPF configuration allowing unrestricted email sending")
        
        dmarc_record = analysis_results.get('dmarc', {}).get('record', {})
        if not dmarc_record.get('valid'):
            roadmap["immediate"].append("Implement basic DMARC policy for monitoring (p=none)")
        
        # Short-term actions (foundational security improvements)
        spf_record = analysis_results.get('spf', {}).get('record', {})
        if not spf_record.get('valid'):
            roadmap["short_term"].append("Implement SPF record for email authentication")
        
        dkim_selectors = analysis_results.get('dkim', {}).get('selectors', {})
        if not any(data.get('record', {}).get('valid', False) for data in dkim_selectors.values()):
            roadmap["short_term"].append("Configure DKIM signing for outgoing emails")
        
        dmarc_policy = analysis_results.get('dmarc', {}).get('record', {}).get('tags', {}).get('p', 'none')
        if dmarc_policy == 'none':
            roadmap["short_term"].append("Upgrade DMARC policy to quarantine after monitoring legitimate traffic")
        
        # Long-term actions (advanced security features)
        if dmarc_policy in ['none', 'quarantine']:
            roadmap["long_term"].append("Upgrade to DMARC reject policy for maximum protection")
        
        additional_records = analysis_results.get('additional', {}).get('records', {})
        if not additional_records.get('mta_sts', {}).get('valid'):
            roadmap["long_term"].append("Implement MTA-STS for transport security")
        
        if not additional_records.get('tls_rpt', {}).get('valid'):
            roadmap["long_term"].append("Implement TLS-RPT for delivery monitoring")
        
        if not additional_records.get('bimi', {}).get('valid') and dmarc_policy in ['quarantine', 'reject']:
            roadmap["long_term"].append("Consider BIMI implementation for brand logo authentication")
        
        return roadmap