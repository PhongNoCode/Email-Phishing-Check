from rich.console import Console
from core.email_analyzer.risk_policy import HEADER_SCORES

console = Console()

def check_urgent_headers(urgent_headers):
    if not urgent_headers:
        console.print(f"[dim]\\[check_urgent_headers][/dim] Result: Safe header | Added score: [green]+0[/green]")
        return 0
        
    console.print(f"[dim]\\[check_urgent_headers][/dim] Result: Urgent headers detected | Added score: [red]+{HEADER_SCORES['urgent_header']}[/red]")
    return HEADER_SCORES['urgent_header']
