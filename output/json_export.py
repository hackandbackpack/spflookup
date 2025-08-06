"""
JSON export formatter for email security analysis results.
"""
import json
from typing import Dict, Any, Optional
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


class JSONExporter:
    """Exports email security analysis results to JSON format."""
    
    def __init__(self, indent: int = 2, sort_keys: bool = True):
        self.indent = indent
        self.sort_keys = sort_keys
    
    def format_analysis(self, domain: str, analysis_results: Dict[str, Any]) -> str:
        """Format complete analysis results as JSON string."""
        
        # Create comprehensive JSON structure
        json_output = {
            "metadata": {
                "domain": domain,
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "tool": "spf-lookup",
                "version": "1.0.0"
            },
            "summary": self._create_summary(analysis_results),
            "records": self._format_records(analysis_results),
            "analysis": self._format_analysis_results(analysis_results),
            "threat_intelligence": self._format_threat_intelligence(analysis_results.get('threat_intel', {})),
            "recommendations": analysis_results.get('recommendations', [])
        }
        
        return json.dumps(json_output, indent=self.indent, sort_keys=self.sort_keys, ensure_ascii=False)
    
    def save_to_file(self, domain: str, analysis_results: Dict[str, Any], filename: str) -> bool:
        """Save analysis results to JSON file."""
        try:
            json_content = self.format_analysis(domain, analysis_results)
            
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(json_content)
            
            logger.info(f"Analysis results saved to {filename}")
            return True
        
        except Exception as e:
            logger.error(f"Failed to save JSON to {filename}: {e}")
            return False
    
    def _create_summary(self, analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """Create high-level summary of email security posture."""
        summary = {
            "records_found": {},
            "security_status": {},
            "overall_score": None  # No scoring as requested
        }
        
        # SPF Summary
        spf_data = analysis_results.get('spf', {})
        spf_record = spf_data.get('record', {})
        summary["records_found"]["spf"] = spf_record.get('valid', False)
        summary["security_status"]["spf"] = spf_data.get('analysis', {}).get('level', 'unknown')
        
        # DMARC Summary
        dmarc_data = analysis_results.get('dmarc', {})
        dmarc_record = dmarc_data.get('record', {})
        summary["records_found"]["dmarc"] = dmarc_record.get('valid', False)
        summary["security_status"]["dmarc"] = dmarc_data.get('analysis', {}).get('level', 'unknown')
        
        # DKIM Summary
        dkim_data = analysis_results.get('dkim', {})
        dkim_selectors = dkim_data.get('selectors', {})
        valid_dkim_count = sum(1 for s in dkim_selectors.values() if s.get('record', {}).get('valid', False))
        summary["records_found"]["dkim"] = valid_dkim_count > 0
        summary["security_status"]["dkim"] = f"{valid_dkim_count}_selectors_found"
        
        # Additional Records Summary
        additional_data = analysis_results.get('additional', {})
        additional_records = additional_data.get('records', {})
        
        for record_type in ['bimi', 'mta_sts', 'tls_rpt']:
            record_data = additional_records.get(record_type, {})
            summary["records_found"][record_type] = bool(record_data and record_data.get('valid'))
        
        # Threat Intelligence Summary
        threat_intel = analysis_results.get('threat_intel', {})
        reputation = threat_intel.get('reputation', {})
        summary["security_status"]["reputation"] = reputation.get('overall_status', 'unknown')
        
        return summary
    
    def _format_records(self, analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """Format all discovered email security records."""
        records = {}
        
        # SPF Record
        spf_data = analysis_results.get('spf', {})
        spf_record = spf_data.get('record', {})
        if spf_record:
            records["spf"] = {
                "valid": spf_record.get('valid', False),
                "raw_record": spf_record.get('raw_record', ''),
                "version": spf_record.get('version', ''),
                "mechanisms": spf_record.get('mechanisms', []),
                "modifiers": spf_record.get('modifiers', {}),
                "dns_lookups": spf_record.get('dns_lookups', 0),
                "warnings": spf_record.get('warnings', []),
                "errors": spf_record.get('errors', [])
            }
        
        # DMARC Record
        dmarc_data = analysis_results.get('dmarc', {})
        dmarc_record = dmarc_data.get('record', {})
        if dmarc_record:
            records["dmarc"] = {
                "valid": dmarc_record.get('valid', False),
                "raw_record": dmarc_record.get('raw_record', ''),
                "version": dmarc_record.get('version', ''),
                "tags": dmarc_record.get('tags', {}),
                "warnings": dmarc_record.get('warnings', []),
                "errors": dmarc_record.get('errors', [])
            }
        
        # DKIM Records
        dkim_data = analysis_results.get('dkim', {})
        dkim_selectors = dkim_data.get('selectors', {})
        if dkim_selectors:
            records["dkim"] = {}
            for selector, selector_data in dkim_selectors.items():
                record_data = selector_data.get('record', {})
                records["dkim"][selector] = {
                    "valid": record_data.get('valid', False),
                    "raw_record": record_data.get('raw_record', ''),
                    "tags": record_data.get('tags', {}),
                    "key_info": record_data.get('key_info', {}),
                    "warnings": record_data.get('warnings', []),
                    "errors": record_data.get('errors', [])
                }
        
        # Additional Records
        additional_data = analysis_results.get('additional', {})
        additional_records = additional_data.get('records', {})
        
        for record_type, record_data in additional_records.items():
            if record_data and record_type != 'policy':  # Skip MTA-STS policy for records section
                records[record_type] = {
                    "valid": record_data.get('valid', False),
                    "raw_record": record_data.get('raw_record', ''),
                    "version": record_data.get('version', ''),
                    "tags": record_data.get('tags', {}),
                    "warnings": record_data.get('warnings', []),
                    "errors": record_data.get('errors', [])
                }
        
        # MTA-STS Policy (if present)
        mta_sts_policy = additional_records.get('policy', {})
        if mta_sts_policy:
            records["mta_sts_policy"] = {
                "valid": mta_sts_policy.get('valid', False),
                "url": mta_sts_policy.get('url', ''),
                "directives": mta_sts_policy.get('directives', {}),
                "warnings": mta_sts_policy.get('warnings', []),
                "errors": mta_sts_policy.get('errors', [])
            }
        
        return records
    
    def _format_analysis_results(self, analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """Format security analysis results."""
        analysis = {}
        
        # SPF Analysis
        spf_analysis = analysis_results.get('spf', {}).get('analysis', {})
        if spf_analysis:
            analysis["spf"] = {
                "level": spf_analysis.get('level', 'unknown'),
                "description": spf_analysis.get('description', ''),
                "strengths": spf_analysis.get('strengths', []),
                "security_issues": spf_analysis.get('security_issues', []),
                "recommendations": spf_analysis.get('recommendations', [])
            }
        
        # DMARC Analysis
        dmarc_analysis = analysis_results.get('dmarc', {}).get('analysis', {})
        if dmarc_analysis:
            analysis["dmarc"] = {
                "level": dmarc_analysis.get('level', 'unknown'),
                "description": dmarc_analysis.get('description', ''),
                "strengths": dmarc_analysis.get('strengths', []),
                "security_issues": dmarc_analysis.get('security_issues', []),
                "recommendations": dmarc_analysis.get('recommendations', [])
            }
        
        # DKIM Analysis
        dkim_data = analysis_results.get('dkim', {})
        dkim_selectors = dkim_data.get('selectors', {})
        if dkim_selectors:
            analysis["dkim"] = {}
            for selector, selector_data in dkim_selectors.items():
                selector_analysis = selector_data.get('analysis', {})
                if selector_analysis:
                    analysis["dkim"][selector] = {
                        "level": selector_analysis.get('level', 'unknown'),
                        "description": selector_analysis.get('description', ''),
                        "strengths": selector_analysis.get('strengths', []),
                        "security_issues": selector_analysis.get('security_issues', []),
                        "recommendations": selector_analysis.get('recommendations', [])
                    }
        
        # Additional Records Analysis
        additional_data = analysis_results.get('additional', {})
        additional_analysis = additional_data.get('analysis', {})
        if additional_analysis:
            analysis["additional_records"] = {
                "bimi": additional_analysis.get('bimi', {}),
                "mta_sts": additional_analysis.get('mta_sts', {}),
                "tls_rpt": additional_analysis.get('tls_rpt', {}),
                "overall_recommendations": additional_analysis.get('overall_recommendations', [])
            }
        
        return analysis
    
    def _format_threat_intelligence(self, threat_intel: Dict[str, Any]) -> Dict[str, Any]:
        """Format threat intelligence data."""
        if not threat_intel:
            return {}
        
        reputation = threat_intel.get('reputation', {})
        subdomain_analysis = threat_intel.get('subdomain_analysis', {})
        
        formatted_threat_intel = {
            "reputation": {
                "overall_status": reputation.get('overall_status', 'unknown'),
                "warnings": reputation.get('warnings', []),
                "security_notes": reputation.get('security_notes', []),
                "checks": reputation.get('checks', {})
            }
        }
        
        if subdomain_analysis:
            formatted_threat_intel["subdomain_analysis"] = subdomain_analysis
        
        return formatted_threat_intel
    
    def create_minimal_json(self, domain: str, analysis_results: Dict[str, Any]) -> str:
        """Create a minimal JSON output with only essential information."""
        
        minimal_output = {
            "domain": domain,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "spf": self._get_minimal_record_status(analysis_results, 'spf'),
            "dmarc": self._get_minimal_record_status(analysis_results, 'dmarc'),
            "dkim": self._get_minimal_dkim_status(analysis_results),
            "recommendations": analysis_results.get('recommendations', [])
        }
        
        return json.dumps(minimal_output, indent=self.indent, sort_keys=self.sort_keys)
    
    def _get_minimal_record_status(self, analysis_results: Dict[str, Any], record_type: str) -> Dict[str, Any]:
        """Get minimal status for a record type."""
        record_data = analysis_results.get(record_type, {}).get('record', {})
        analysis_data = analysis_results.get(record_type, {}).get('analysis', {})
        
        return {
            "present": record_data.get('valid', False),
            "level": analysis_data.get('level', 'unknown'),
            "issues": len(record_data.get('errors', [])) + len(record_data.get('warnings', []))
        }
    
    def _get_minimal_dkim_status(self, analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """Get minimal DKIM status."""
        dkim_data = analysis_results.get('dkim', {})
        selectors = dkim_data.get('selectors', {})
        
        valid_selectors = [s for s, data in selectors.items() if data.get('record', {}).get('valid', False)]
        
        return {
            "present": len(valid_selectors) > 0,
            "selectors_found": len(valid_selectors),
            "total_selectors_checked": len(selectors),
            "valid_selectors": valid_selectors
        }