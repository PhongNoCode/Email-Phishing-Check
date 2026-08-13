from rich.console import Console
from core.email_analyzer.risk_policy import BODY_SCORES

console = Console()

def check_urgent_body(urgent_body):
    if not urgent_body:
        console.print(f"[dim]\\[check_urgent_body][/dim] Result: Safe body | Added score: [green]+0[/green]")
        return 0
    console.print(f"[dim]\\[check_urgent_body][/dim] Result: Urgent body detected | Added score: [red]+{BODY_SCORES['dangerous_content']}[/red]")
    return BODY_SCORES['dangerous_content']
