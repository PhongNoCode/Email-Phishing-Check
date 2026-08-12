from rich.console import Console
from core.email_analyzer.risk_policy import AUTHENTICATION_SCORES

console = Console()

def check_from_vs_return_path(header):
    if 'email_domain_from' in header and 'email_domain_return_path' in header:
        if header['email_domain_from'] != header['email_domain_return_path']:
            console.print(f"[dim]\\[check_from_vs_return_path][/dim] Result: Mismatch detected | Added score: [red]+{AUTHENTICATION_SCORES['from_vs_return_path']}[/red]")
            return AUTHENTICATION_SCORES['from_vs_return_path']
        else:
            console.print("[dim]\\[check_from_vs_return_path][/dim] Result: Domains match | Added score: [green]+0[/green]")
            return 0
    else:
        console.print("[dim]\\[check_from_vs_return_path][/dim] Result: Header keys missing | Added score: [green]+0[/green]")
        return 0

def check_from_vs_reply_to(header):
    if 'email_domain_from' in header and 'email_domain_reply_to' in header:
        if header['email_domain_from'] != header['email_domain_reply_to']:
            console.print(f"[dim]\\[check_from_vs_reply_to][/dim] Result: Mismatch detected | Added score: [red]+{AUTHENTICATION_SCORES['from_vs_reply_to']}[/red]")
            return AUTHENTICATION_SCORES['from_vs_reply_to']
        else:
            console.print("[dim]\\[check_from_vs_reply_to][/dim] Result: Domains match | Added score: [green]+0[/green]")
            return 0
    console.print("[dim]\\[check_from_vs_reply_to][/dim] Result: Evident is not clear | Added score: [green]+0[/green]")
    return 0

def check_from_vs_message_id(route, header):
    if 'email_domain_message_id' in route and 'email_domain_from' in header:
        if route['email_domain_message_id'] != header['email_domain_from']:
            console.print(f"[dim]\\[check_from_vs_message_id][/dim] Result: Mismatch detected | Added score: [red]+{AUTHENTICATION_SCORES['from_vs_message_id']}[/red]")
            return AUTHENTICATION_SCORES['from_vs_message_id']
        else:
            console.print("[dim]\\[check_from_vs_message_id][/dim] Result: Domains match | Added score: [green]+0[/green]")
            return 0
    console.print(f"[dim]\\[email_domain_message_id][/dim] Result: Evident is not clear | Added score: [green]+0[/green]")
    return 0

def check_dkim_signature(header):
    if 'dkim_signature' in header:
        if header['dkim_signature'] == True:
            console.print(f"[dim]\\[check_dkim_signature][/dim] Result: Invalid signature | Added score: [red]+{AUTHENTICATION_SCORES['fail_dkim']}[/red]")
            return AUTHENTICATION_SCORES['fail_dkim']
        else:
            console.print("[dim]\\[check_dkim_signature][/dim] Result: Valid signature | Added score: [green]+0[/green]")
            return 0
    else:
        console.print("[dim]\\[check_dkim_signature][/dim] Result: Header key missing | Added score: [green]+0[/green]")
        return 0

def check_spf(header):
    if 'receive_spf' in header:
        if header['receive_spf'] == True:
            console.print(f"[dim]\\[check_spf][/dim] Result: Invalid SPF | Added score: [red]+{AUTHENTICATION_SCORES['not_pass_spf']}[/red]")
            return AUTHENTICATION_SCORES['not_pass_spf']
        else:
            console.print("[dim]\\[check_spf][/dim] Result: Valid SPF | Added score: [green]+0[/green]")
            return 0
    else:
        console.print("[dim]\\[check_spf][/dim] Result: Header key missing | Added score: [green]+0[/green]")
        return 0
