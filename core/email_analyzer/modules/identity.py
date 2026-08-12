from rich.console import Console
from core.email_analyzer.risk_policy import IDENTITY_SCORES

console = Console()
            
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

def check_typo(typo):
    total_score_typo = 0
    if typo['email_domain_from'] == 1:
        total_score_typo += IDENTITY_SCORES['typo_from']
        console.print(f"[dim]\\[check_typo][/dim] Result: Typo of from suspicious | Added score: [red]+{IDENTITY_SCORES['typo_from']}[/red]")
    else:
        console.print(f"[dim]\\[check_typo][/dim] Result: Typo of from clean | Added score: [green]+0[/green]")

    if typo['email_domain_reply_to'] == 1:
        total_score_typo += IDENTITY_SCORES['typo_reply_to']
        console.print(f"[dim]\\[check_typo][/dim] Result: Typo of reply to suspicious | Added score: [orange1]+{IDENTITY_SCORES['typo_reply_to']}[/orange1]")
    else:
        console.print(f"[dim]\\[check_typo][/dim] Result: Typo of reply to clean | Added score: [green]+0[/green]")

    if typo['email_domain_return_path'] == 1:
        total_score_typo += IDENTITY_SCORES['typo_return_path']
        console.print(f"[dim]\\[check_typo][/dim] Result: Typo of return path suspicious | Added score: [orange1]+{IDENTITY_SCORES['typo_return_path']}[/orange1]")
    else:
        console.print(f"[dim]\\[check_typo][/dim] Result: Typo of return path clean | Added score: [green]+0[/green]")

    if typo['email_domain_url'] == 1:
        total_score_typo += IDENTITY_SCORES['typo_url']
        console.print(f"[dim]\\[check_typo][/dim] Result: Typo of url suspicious | Added score: [red]+{IDENTITY_SCORES['typo_url']}[/red]")
    else:
        console.print(f"[dim]\\[check_typo][/dim] Result: Typo of url clean | Added score: [green]+0[/green]")
        
    return total_score_typo
