"""
Rich console output formatter for email security analysis.
"""
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.tree import Tree
from rich import box
from typing import Dict, List, Any
import logging

logger = logging.getLogger(__name__)


class ConsoleFormatter:
    """Formats email security analysis results for console output."""
    
    def __init__(self, console: Console = None):
        self.console = console or Console()
    
    def print_analysis(self, domain: str, analysis_results: Dict[str, Any]) -> None:
        """Print complete email security analysis to console."""
        
        # Header
        self.console.print(f"\n[bold blue]Email Security Analysis for: {domain}[/bold blue]")
        self.console.print("=" * (len(domain) + 35), style="blue")
        
        # SPF Analysis
        if 'spf' in analysis_results:
            self._print_spf_analysis(analysis_results['spf'])
        
        # DMARC Analysis
        if 'dmarc' in analysis_results:
            self._print_dmarc_analysis(analysis_results['dmarc'])
        
        # DKIM Analysis
        if 'dkim' in analysis_results:
            self._print_dkim_analysis(analysis_results['dkim'])
        
        # Additional Records
        if 'additional' in analysis_results:
            self._print_additional_records(analysis_results['additional'])
        
        # Threat Intelligence
        if 'threat_intel' in analysis_results:
            self._print_threat_intelligence(analysis_results['threat_intel'])
        
        # Recommendations
        if 'recommendations' in analysis_results:
            self._print_recommendations(analysis_results['recommendations'])
    
    def _print_spf_analysis(self, spf_data: Dict[str, Any]) -> None:
        """Print SPF analysis results."""
        record_data = spf_data.get('record', {})
        analysis = spf_data.get('analysis', {})
        
        # SPF Record Panel
        if record_data.get('valid'):
            status = "[green]✓ Valid[/green]"
            raw_record = record_data.get('raw_record', 'N/A')
        else:
            status = "[red]✗ Invalid/Missing[/red]"
            raw_record = record_data.get('error', 'No SPF record found')
        
        spf_panel = Panel(
            f"[bold]Status:[/bold] {status}\n"
            f"[bold]Record:[/bold] {raw_record}\n"
            f"[bold]DNS Lookups:[/bold] {record_data.get('dns_lookups', 0)}/10",
            title="[bold cyan]SPF Record[/bold cyan]",
            border_style="cyan"
        )
        self.console.print(spf_panel)
        
        # SPF Mechanisms Table
        if record_data.get('valid') and record_data.get('mechanisms'):
            mechanisms_table = Table(title="SPF Mechanisms", box=box.ROUNDED)
            mechanisms_table.add_column("Type", style="bold")
            mechanisms_table.add_column("Qualifier", justify="center")
            mechanisms_table.add_column("Value", style="dim")
            
            for mechanism in record_data['mechanisms']:
                qualifier_style = self._get_qualifier_style(mechanism.get('qualifier', '+'))
                mechanisms_table.add_row(
                    mechanism.get('type', '').upper(),
                    f"[{qualifier_style}]{mechanism.get('qualifier', '+')}[/{qualifier_style}]",
                    self._format_mechanism_value(mechanism)
                )
            
            self.console.print(mechanisms_table)
        
        # SPF Analysis
        if analysis:
            self._print_analysis_section("SPF Analysis", analysis)
        
        # Warnings and Errors
        self._print_issues(record_data.get('warnings', []), record_data.get('errors', []))
    
    def _print_dmarc_analysis(self, dmarc_data: Dict[str, Any]) -> None:
        """Print DMARC analysis results."""
        record_data = dmarc_data.get('record', {})
        analysis = dmarc_data.get('analysis', {})
        
        # DMARC Record Panel
        if record_data.get('valid'):
            status = "[green]✓ Valid[/green]"
            policy = record_data.get('tags', {}).get('p', 'unknown')
            policy_color = self._get_policy_color(policy)
        else:
            status = "[red]✗ Invalid/Missing[/red]"
            policy = "None"
            policy_color = "red"
        
        dmarc_panel = Panel(
            f"[bold]Status:[/bold] {status}\n"
            f"[bold]Policy:[/bold] [{policy_color}]{policy}[/{policy_color}]\n"
            f"[bold]Record:[/bold] {record_data.get('raw_record', 'No DMARC record found')}",
            title="[bold magenta]DMARC Policy[/bold magenta]",
            border_style="magenta"
        )
        self.console.print(dmarc_panel)
        
        # DMARC Tags Table
        if record_data.get('valid') and record_data.get('tags'):
            tags_table = Table(title="DMARC Configuration", box=box.ROUNDED)
            tags_table.add_column("Tag", style="bold")
            tags_table.add_column("Value", style="dim")
            tags_table.add_column("Description")
            
            tag_descriptions = {
                'v': 'Version',
                'p': 'Domain Policy',
                'sp': 'Subdomain Policy',
                'adkim': 'DKIM Alignment',
                'aspf': 'SPF Alignment',
                'pct': 'Percentage',
                'fo': 'Failure Options',
                'rua': 'Aggregate Reports',
                'ruf': 'Failure Reports'
            }
            
            for tag, value in record_data['tags'].items():
                description = tag_descriptions.get(tag, 'Unknown')
                if isinstance(value, list):
                    value_str = ', '.join(str(v) for v in value)
                else:
                    value_str = str(value)
                
                tags_table.add_row(tag.upper(), value_str, description)
            
            self.console.print(tags_table)
        
        # DMARC Analysis
        if analysis:
            self._print_analysis_section("DMARC Analysis", analysis)
        
        # Warnings and Errors
        self._print_issues(record_data.get('warnings', []), record_data.get('errors', []))
    
    def _print_dkim_analysis(self, dkim_data: Dict[str, Any]) -> None:
        """Print DKIM analysis results."""
        selectors = dkim_data.get('selectors', {})
        
        if not selectors:
            dkim_panel = Panel(
                "[red]No DKIM records found[/red]\n"
                "Searched common selectors but found no valid DKIM configurations.",
                title="[bold yellow]DKIM Records[/bold yellow]",
                border_style="yellow"
            )
            self.console.print(dkim_panel)
            return
        
        # DKIM Overview Panel
        valid_selectors = [s for s, data in selectors.items() if data.get('record', {}).get('valid')]
        
        dkim_panel = Panel(
            f"[bold]Found Selectors:[/bold] {len(selectors)}\n"
            f"[bold]Valid Selectors:[/bold] [green]{len(valid_selectors)}[/green]\n"
            f"[bold]Selectors:[/bold] {', '.join(selectors.keys())}",
            title="[bold yellow]DKIM Records[/bold yellow]",
            border_style="yellow"
        )
        self.console.print(dkim_panel)
        
        # Individual Selector Details
        for selector, selector_data in selectors.items():
            record_data = selector_data.get('record', {})
            analysis = selector_data.get('analysis', {})
            
            if record_data.get('valid'):
                status = "[green]✓ Valid[/green]"
                key_info = record_data.get('key_info', {})
                key_type = key_info.get('type', 'Unknown')
                key_size = key_info.get('size', 'Unknown')
                key_strength = key_info.get('strength', 'Unknown')
            else:
                status = "[red]✗ Invalid[/red]"
                key_type = key_size = key_strength = "N/A"
            
            selector_panel = Panel(
                f"[bold]Status:[/bold] {status}\n"
                f"[bold]Key Type:[/bold] {key_type}\n"
                f"[bold]Key Size:[/bold] {key_size} bits\n"
                f"[bold]Strength:[/bold] {key_strength}",
                title=f"[bold dim]Selector: {selector}[/bold dim]",
                border_style="dim"
            )
            self.console.print(selector_panel)
            
            # Analysis for this selector
            if analysis and record_data.get('valid'):
                self._print_analysis_section(f"DKIM Analysis ({selector})", analysis)
        
        # Combined warnings and errors
        all_warnings = []
        all_errors = []
        for selector_data in selectors.values():
            record_data = selector_data.get('record', {})
            all_warnings.extend(record_data.get('warnings', []))
            all_errors.extend(record_data.get('errors', []))
        
        if all_warnings or all_errors:
            self._print_issues(all_warnings, all_errors)
    
    def _print_additional_records(self, additional_data: Dict[str, Any]) -> None:
        """Print additional email security records."""
        records = additional_data.get('records', {})
        analysis = additional_data.get('analysis', {})
        
        if not records:
            return
        
        # Additional Records Overview
        additional_panel = Panel(
            self._format_additional_records_summary(records),
            title="[bold green]Additional Email Security Records[/bold green]",
            border_style="green"
        )
        self.console.print(additional_panel)
        
        # Individual record details
        for record_type, record_data in records.items():
            if record_data and record_type != 'policy':  # Skip MTA-STS policy for main display
                self._print_record_details(record_type.upper(), record_data)
    
    def _print_threat_intelligence(self, threat_intel: Dict[str, Any]) -> None:
        """Print threat intelligence analysis."""
        reputation = threat_intel.get('reputation', {})
        
        if not reputation:
            return
        
        overall_status = reputation.get('overall_status', 'unknown')
        status_color = "green" if overall_status == "clean" else "red" if overall_status == "suspicious" else "yellow"
        
        # Threat Intelligence Panel
        checks = reputation.get('checks', {})
        blacklist = checks.get('blacklist_status', {})
        mx_info = checks.get('mx_reputation', {})
        
        threat_panel = Panel(
            f"[bold]Overall Status:[/bold] [{status_color}]{overall_status.title()}[/{status_color}]\n"
            f"[bold]Blacklist Status:[/bold] {blacklist.get('status', 'unknown').title()}\n"
            f"[bold]Blacklists Checked:[/bold] {blacklist.get('total_checked', 0)}\n"
            f"[bold]Email Providers:[/bold] {', '.join(mx_info.get('providers', ['Unknown']))}",
            title="[bold red]Threat Intelligence[/bold red]",
            border_style="red"
        )
        self.console.print(threat_panel)
        
        # Warnings and security notes
        warnings = reputation.get('warnings', [])
        security_notes = reputation.get('security_notes', [])
        if warnings or security_notes:
            self._print_issues(security_notes, warnings)
    
    def _print_recommendations(self, recommendations: List[str]) -> None:
        """Print security recommendations."""
        if not recommendations:
            return
        
        rec_text = "\n".join(f"• {rec}" for rec in recommendations)
        
        rec_panel = Panel(
            rec_text,
            title="[bold cyan]Security Recommendations[/bold cyan]",
            border_style="cyan"
        )
        self.console.print(rec_panel)
    
    def _print_analysis_section(self, title: str, analysis: Dict[str, Any]) -> None:
        """Print an analysis section."""
        level = analysis.get('level', 'unknown')
        description = analysis.get('description', '')
        
        level_color = {
            'strict': 'green',
            'strong': 'green', 
            'moderate': 'yellow',
            'weak': 'red',
            'dangerous': 'red',
            'none': 'red',
            'monitoring': 'yellow'
        }.get(level, 'white')
        
        content = f"[bold]Level:[/bold] [{level_color}]{level.title()}[/{level_color}]\n"
        if description:
            content += f"[bold]Description:[/bold] {description}\n"
        
        # Add strengths
        strengths = analysis.get('strengths', [])
        if strengths:
            content += f"[bold green]Strengths:[/bold green]\n"
            for strength in strengths:
                content += f"  ✓ {strength}\n"
        
        # Add security issues
        security_issues = analysis.get('security_issues', [])
        if security_issues:
            content += f"[bold red]Security Issues:[/bold red]\n"
            for issue in security_issues:
                content += f"  ⚠ {issue}\n"
        
        analysis_panel = Panel(
            content.rstrip(),
            title=f"[bold dim]{title}[/bold dim]",
            border_style="dim"
        )
        self.console.print(analysis_panel)
    
    def _print_issues(self, warnings: List[str], errors: List[str]) -> None:
        """Print warnings and errors."""
        if not warnings and not errors:
            return
        
        issues_text = ""
        
        if errors:
            issues_text += "[bold red]Errors:[/bold red]\n"
            for error in errors:
                issues_text += f"  ✗ {error}\n"
        
        if warnings:
            if errors:
                issues_text += "\n"
            issues_text += "[bold yellow]Warnings:[/bold yellow]\n"
            for warning in warnings:
                issues_text += f"  ⚠ {warning}\n"
        
        issues_panel = Panel(
            issues_text.rstrip(),
            title="[bold]Issues[/bold]",
            border_style="yellow"
        )
        self.console.print(issues_panel)
    
    def _format_additional_records_summary(self, records: Dict[str, Any]) -> str:
        """Format summary of additional records."""
        summary = []
        
        for record_type, record_data in records.items():
            if record_type == 'policy':  # Skip MTA-STS policy
                continue
            
            if record_data and record_data.get('valid'):
                summary.append(f"[green]✓[/green] {record_type.upper()}")
            elif record_data:
                summary.append(f"[red]✗[/red] {record_type.upper()}")
            else:
                summary.append(f"[dim]−[/dim] {record_type.upper()}")
        
        return "  ".join(summary) if summary else "No additional records found"
    
    def _print_record_details(self, record_type: str, record_data: Dict[str, Any]) -> None:
        """Print details for a specific record type."""
        if record_data.get('valid'):
            status = "[green]✓ Valid[/green]"
        else:
            status = "[red]✗ Invalid[/red]"
        
        content = f"[bold]Status:[/bold] {status}\n"
        
        tags = record_data.get('tags', {})
        if tags:
            for tag, value in tags.items():
                if isinstance(value, list):
                    value_str = ', '.join(str(v) for v in value)
                else:
                    value_str = str(value)
                content += f"[bold]{tag.upper()}:[/bold] {value_str}\n"
        
        record_panel = Panel(
            content.rstrip(),
            title=f"[bold dim]{record_type} Record[/bold dim]",
            border_style="dim"
        )
        self.console.print(record_panel)
    
    def _get_qualifier_style(self, qualifier: str) -> str:
        """Get color style for SPF qualifier."""
        qualifier_styles = {
            '+': 'green',
            '-': 'red', 
            '~': 'yellow',
            '?': 'blue'
        }
        return qualifier_styles.get(qualifier, 'white')
    
    def _get_policy_color(self, policy: str) -> str:
        """Get color for DMARC policy."""
        policy_colors = {
            'reject': 'green',
            'quarantine': 'yellow',
            'none': 'red'
        }
        return policy_colors.get(policy.lower(), 'white')
    
    def _format_mechanism_value(self, mechanism: Dict[str, Any]) -> str:
        """Format mechanism value for display."""
        mech_type = mechanism.get('type', '')
        
        if mech_type == 'include':
            return mechanism.get('domain', '')
        elif mech_type in ['a', 'mx', 'ptr', 'exists']:
            domain = mechanism.get('domain', '')
            cidr = mechanism.get('cidr', '')
            return f"{domain}{f'/{cidr}' if cidr else ''}"
        elif mech_type in ['ip4', 'ip6']:
            ip = mechanism.get('ip', '')
            cidr = mechanism.get('cidr', '')
            return f"{ip}{f'/{cidr}' if cidr else ''}"
        elif mech_type == 'all':
            return ''
        else:
            return mechanism.get('raw', '')