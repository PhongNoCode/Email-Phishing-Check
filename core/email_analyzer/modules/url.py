from rich.console import Console
from core.email_analyzer.risk_policy import URL_SCORES

console = Console()

def check_urls(url):
    if not url:
        console.print("[dim]\\[check_urls][/dim] Result: No URL | Added score: [green]+0[/green]")
        return 0
        
    highest_score = sorted(url.values())[0]
    if highest_score == 0:
        console.print(f"[dim]\\[check_urls][/dim] Result: Raw IP detected | Added score: [red]+{URL_SCORES['raw_ip']}[/red]")
        return URL_SCORES['raw_ip']
    elif highest_score == 1:
        console.print(f"[dim]\\[check_urls][/dim] Result: Shortened IP detected | Added score: [orange]+{URL_SCORES['shortened']}[/orange]")
        return URL_SCORES['shortened']
    else:
        console.print(f"[dim]\\[check_urls][/dim] Result: URLs is clean | Added score: [green]+0[/green]")
        return 0
