from rich.console import Console
from core.email_analyzer.risk_policy import HEADER_SCORES, IDENTITY_SCORES

console = Console()

def check_urgent_headers(urgent_headers):
    if not urgent_headers:
        console.print(f"[dim]\\[check_urgent_headers][/dim] Result: Safe header | Added score: [green]+0[/green]")
        return 0
        
    console.print(f"[dim]\\[check_urgent_headers][/dim] Result: Urgent headers detected | Added score: [red]+{HEADER_SCORES['urgent_header']}[/red]")
    return HEADER_SCORES['urgent_header']

def check_homoglyph(homoglyph):
    total_score_homo = 0
    if homoglyph['homoglyph_from'] == 1:
        total_score_homo += IDENTITY_SCORES['homoglyph_from']
        console.print(f"[dim]\\[check_homoglyph][/dim] Result: Homoglyph of from suspicious | Added score: [red]+{IDENTITY_SCORES['homoglyph_from']}[/red]")
    else:
        console.print(f"[dim]\\[check_homoglyph][/dim] Result: Homoglyph of from clean | Added score: [green]+0[/green]")

    if homoglyph['homoglyph_reply_to'] == 1:
        total_score_homo += IDENTITY_SCORES['homoglyph_reply_to']
        console.print(f"[dim]\\[check_homoglyph][/dim] Result: Homoglyph of reply to suspicious | Added score: [orange1]+{IDENTITY_SCORES['homoglyph_reply_to']}[/orange1]")
    else:
        console.print(f"[dim]\\[check_homoglyph][/dim] Result: Homoglyph of reply to clean | Added score: [green]+0[/green]")

    if homoglyph['homoglyph_return_path'] == 1:
        total_score_homo += IDENTITY_SCORES['homoglyph_return_path']
        console.print(f"[dim]\\[check_homoglyph][/dim] Result: Homoglyph of return path suspicious | Added score: [orange1]+{IDENTITY_SCORES['homoglyph_return_path']}[/orange1]")
    else:
        console.print(f"[dim]\\[check_homoglyph][/dim] Result: Homoglyph of return path clean | Added score: [green]+0[/green]")

    if homoglyph['homoglyph_url'] == 1:
        total_score_homo += IDENTITY_SCORES['homoglyph_url']
        console.print(f"[dim]\\[check_homoglyph][/dim] Result: Homoglyph of url suspicious | Added score: [red]+{IDENTITY_SCORES['homoglyph_url']}[/red]")
    else:
        console.print(f"[dim]\\[check_homoglyph][/dim] Result: Homoglyph of url clean | Added score: [green]+0[/green]")
    return total_score_homo
