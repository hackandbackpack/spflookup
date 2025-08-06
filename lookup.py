"""
SPF Lookup Tool - Email Security Analysis

A comprehensive tool for analyzing email security posture including SPF, DMARC, DKIM,
and additional security records (BIMI, MTA-STS, TLS-RPT) for domains.
"""

import argparse
import sys
import logging
from typing import Dict, Any
from pathlib import Path

from rich.console import Console
from rich.logging import RichHandler

from core.dns_analyzer import DNSAnalyzer
from core.spf_parser import SPFParser
from core.dmarc_parser import DMARCParser
from core.dkim_validator import DKIMValidator
from core.additional_records import AdditionalRecordsParser
from enrichment.threat_intel import ThreatIntelligence
from enrichment.recommendations import RecommendationsEngine
from output.console import ConsoleFormatter
from output.json_export import JSONExporter


class EmailSecurityAnalyzer:
    """Main email security analysis orchestrator."""
    
    def __init__(self, verbose: bool = False):
        self.console = Console()
        self.verbose = verbose
        self._setup_logging()
        
        # Initialize components
        self.dns_analyzer = DNSAnalyzer()
        self.spf_parser = SPFParser()
        self.dmarc_parser = DMARCParser()
        self.dkim_validator = DKIMValidator()
        self.additional_parser = AdditionalRecordsParser()
        self.threat_intel = ThreatIntelligence()
        self.recommendations_engine = RecommendationsEngine()
        
        # Output formatters
        self.console_formatter = ConsoleFormatter(self.console)
        self.json_exporter = JSONExporter()
    
    def _setup_logging(self):
        """Setup logging configuration."""
        level = logging.DEBUG if self.verbose else logging.WARNING
        
        logging.basicConfig(
            level=level,
            format="%(message)s",
            datefmt="[%X]",
            handlers=[RichHandler(console=self.console)]
        )
    
    def analyze_domain(self, domain: str) -> Dict[str, Any]:
        """Perform comprehensive email security analysis for a domain."""
        
        self.console.print(f"\n[bold blue]Analyzing email security for: {domain}[/bold blue]")
        
        analysis_results = {}
        
        # SPF Analysis
        with self.console.status("[bold green]Analyzing SPF record..."):
            spf_record = self.dns_analyzer.get_spf_record(domain)
            spf_parsed = self.spf_parser.parse_spf_record(spf_record)
            spf_analysis = self.spf_parser.analyze_spf_strength(spf_parsed)
            
            analysis_results['spf'] = {
                'record': {**spf_parsed, 'raw_record': spf_record or ''},
                'analysis': spf_analysis
            }
        
        # DMARC Analysis
        with self.console.status("[bold green]Analyzing DMARC policy..."):
            dmarc_record = self.dns_analyzer.get_dmarc_record(domain)
            dmarc_parsed = self.dmarc_parser.parse_dmarc_record(dmarc_record)
            dmarc_analysis = self.dmarc_parser.analyze_dmarc_strength(dmarc_parsed)
            
            analysis_results['dmarc'] = {
                'record': {**dmarc_parsed, 'raw_record': dmarc_record or ''},
                'analysis': dmarc_analysis
            }
        
        # DKIM Analysis
        with self.console.status("[bold green]Discovering DKIM selectors..."):
            dkim_selectors = self.dns_analyzer.discover_dkim_selectors(domain)
            dkim_results = {}
            
            for selector, record in dkim_selectors.items():
                parsed = self.dkim_validator.parse_dkim_record(record, selector)
                analysis = self.dkim_validator.analyze_dkim_strength(parsed)
                
                dkim_results[selector] = {
                    'record': {**parsed, 'raw_record': record or ''},
                    'analysis': analysis
                }
            
            analysis_results['dkim'] = {'selectors': dkim_results}
        
        # Additional Records Analysis
        with self.console.status("[bold green]Checking additional security records..."):
            additional_records = {
                'bimi': self.dns_analyzer.get_bimi_record(domain),
                'mta_sts': self.dns_analyzer.get_mta_sts_record(domain),
                'tls_rpt': self.dns_analyzer.get_tls_rpt_record(domain)
            }
            
            # Parse additional records
            parsed_additional = {}
            for record_type, record_data in additional_records.items():
                if record_type == 'bimi':
                    parsed_additional[record_type] = self.additional_parser.parse_bimi_record(record_data)
                elif record_type == 'mta_sts':
                    parsed_additional[record_type] = self.additional_parser.parse_mta_sts_record(record_data)
                elif record_type == 'tls_rpt':
                    parsed_additional[record_type] = self.additional_parser.parse_tls_rpt_record(record_data)
                
                # Add raw record
                if parsed_additional.get(record_type):
                    parsed_additional[record_type]['raw_record'] = record_data or ''
            
            # Fetch MTA-STS policy if record exists
            if parsed_additional.get('mta_sts', {}).get('valid'):
                mta_sts_policy = self.additional_parser.fetch_mta_sts_policy(domain)
                parsed_additional['policy'] = mta_sts_policy
            
            # Analyze additional records
            additional_analysis = self.additional_parser.analyze_additional_records(domain, parsed_additional)
            
            analysis_results['additional'] = {
                'records': parsed_additional,
                'analysis': additional_analysis
            }
        
        # Threat Intelligence
        with self.console.status("[bold green]Gathering threat intelligence..."):
            reputation = self.threat_intel.check_domain_reputation(domain)
            subdomain_analysis = self.threat_intel.analyze_subdomain_security(domain)
            
            analysis_results['threat_intel'] = {
                'reputation': reputation,
                'subdomain_analysis': subdomain_analysis
            }
        
        # Generate Recommendations
        with self.console.status("[bold green]Generating recommendations..."):
            recommendations = self.recommendations_engine.generate_recommendations(domain, analysis_results)
            analysis_results['recommendations'] = recommendations
        
        return analysis_results


def main():
    """Main CLI interface."""
    parser = argparse.ArgumentParser(
        description="Comprehensive email security analysis tool for SPF, DMARC, DKIM, and additional security records.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python lookup.py example.com
  python lookup.py example.com --verbose
  python lookup.py example.com --format json --output results.json
  python lookup.py example.com --format json --minimal
        """
    )
    
    parser.add_argument("domain", help="Domain to analyze")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("-f", "--format", choices=["console", "json"], default="console", help="Output format")
    parser.add_argument("-o", "--output", help="Output file (for JSON format)")
    parser.add_argument("--minimal", action="store_true", help="Minimal JSON output with essential information only")
    
    args = parser.parse_args()
    
    # Validate domain
    domain = args.domain.lower().strip()
    if not domain or '/' in domain or ' ' in domain:
        print("Error: Please provide a valid domain name")
        sys.exit(1)
    
    # Initialize analyzer
    analyzer = EmailSecurityAnalyzer(verbose=args.verbose)
    
    try:
        # Perform analysis
        results = analyzer.analyze_domain(domain)
        
        # Output results
        if args.format == "console":
            analyzer.console_formatter.print_analysis(domain, results)
        
        elif args.format == "json":
            if args.minimal:
                json_output = analyzer.json_exporter.create_minimal_json(domain, results)
            else:
                json_output = analyzer.json_exporter.format_analysis(domain, results)
            
            if args.output:
                success = analyzer.json_exporter.save_to_file(domain, results, args.output)
                if success:
                    print(f"Results saved to {args.output}")
                else:
                    print("Error saving results to file")
                    sys.exit(1)
            else:
                print(json_output)
    
    except KeyboardInterrupt:
        print("\nAnalysis interrupted by user")
        sys.exit(1)
    except Exception as e:
        if args.verbose:
            raise
        print(f"Error analyzing domain {domain}: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
