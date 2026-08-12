import threading
import time
from rich.console import Console
from core.utils import api  
from core.email_analyzer.constants import MACRO_DANGEROUS_KEYWORDS
from core.email_analyzer.risk_policy import ATTACHMENT_SCORES, MACRO_LOGIC_SCORES

console = Console()
hash_cache = {}
api_lock = threading.Lock()
api_call_times = []

def check_attachment_hashes(hash_of_file):
    if not hash_of_file:
        console.print(f"[dim]\\[check_attachment_hashes][/dim] Result: No hash found in email | Added score: [green]+0[/green]")
        return 0
        
    for file_name, file_hash in hash_of_file.items():
        if file_hash in hash_cache:
            console.print(f"[dim]\\[check_attachment_hashes][/dim] Result: Get in hash cache | Add score: [yellow]+{hash_cache[file_hash]}[/yellow]")
            return hash_cache[file_hash]

    with api_lock:
        if len(api_call_times) == 4:
            current_time = time.time()
            if current_time - api_call_times[0] <= 60 :
                time.sleep(60 - (current_time - api_call_times[0]) + 0.5)
            api_call_times.pop(0)
        api_call_times.append(time.time())
        
    for hash_entry in hash_of_file.items():
        try:
            api_result = api.check_hash(hash_entry)
        
            if api_result['malicious'] >= 4:
                console.print(f"[dim]\\[check_attachment_hashes][/dim] Result: High malicious score | Added score: [bold red]+{ATTACHMENT_SCORES['high_vt_warnings']}[/bold red]")
                hash_cache[file_hash] = 100
                return ATTACHMENT_SCORES['high_vt_warnings']
                
            else:
                console.print("[dim]\\[check_attachment_hashes][/dim] Result: Low/No malicious score | Added score: [green]+0[/green]")
                hash_cache[file_hash] = 0
                return 0
        except Exception as e:
            console.print(f"[dim]\\[check_attachment_hashes][/dim] Result: Hash not found in VT database for {file_name} | Added score: [green]+0[/green]")
            hash_cache[file_hash] = 0
    console.print(f"[dim]\\[check_attachment_hashes][/dim] Result: No information {file_name} | Added score: [green]+0[/green]")
    return 0
            
def check_file_extensions(ext):
    if not ext:
        console.print("[dim]\\[check_file_extensions][/dim] Result: No attachment | Added score: [green]+0[/green]")
        return 0
        
    highest_score = sorted(ext.values())[0]
    if highest_score == 0:
        console.print(f"[dim]\\[check_file_extensions][/dim] Result: Mismatch extension from mail and file | Added score: [red]+{ATTACHMENT_SCORES['ext_mismatch']}[/red]")
        return ATTACHMENT_SCORES['ext_mismatch']
    elif highest_score == 1:
        console.print(f"[dim]\\[check_file_extensions][/dim] Result: Dangerous extension | Added score: [orange1]+{ATTACHMENT_SCORES['dangerous_ext']}[/orange1]")
        return ATTACHMENT_SCORES['dangerous_ext']
    else: 
        console.print("[dim]\\[check_file_extensions][/dim] Result: Extension is clear | Added score: [green]+0[/green]")
        return 0

def check_macros(macro_analysis):
    total_macro_score = 0
    for macro in macro_analysis:

        autoexec_kw = macro.get('autoexec_keywords', [])
        suspicious_kw = macro.get('suspicious_keywords', [])
        patterns = macro.get('patterns', [])

        if (len(autoexec_kw) > 0 and len(suspicious_kw) > 0) or (len(patterns) > 0):
            console.print(f"[dim]\\[check_macros][/dim] Result: Macros autoexec keyword and suspicious key word ; or pattern detected | Added score: [red]+{ATTACHMENT_SCORES['macro_risk_high']}[/red]")
            return ATTACHMENT_SCORES['macro_risk_high']
        
        for word in suspicious_kw:
            kw = word.split(':')[1].strip()
            if kw in MACRO_DANGEROUS_KEYWORDS:
                console.print(f"[dim]\\[check_macros][/dim] Result: Macros dangerous keyword detected | Added score: [red]+{ATTACHMENT_SCORES['macro_risk_high']}[/red]")
                return ATTACHMENT_SCORES['macro_risk_high']

        current_score = 0
        if macro.get('suspicious', 0) > 0:
            current_score += MACRO_LOGIC_SCORES['has_suspicious_flag']

        if len(autoexec_kw) > 1:
            current_score += MACRO_LOGIC_SCORES['autoexec_many']
        elif len(autoexec_kw) == 1:
            current_score += MACRO_LOGIC_SCORES['autoexec_1']

        if len(suspicious_kw) > 1:
            current_score += MACRO_LOGIC_SCORES['suspicious_kw_many']
        elif len(suspicious_kw) == 1:
            current_score += MACRO_LOGIC_SCORES['suspicious_kw_1']

        if len(patterns) > 1:
            current_score += MACRO_LOGIC_SCORES['pattern_many']
        elif len(patterns) == 1:
            current_score += MACRO_LOGIC_SCORES['pattern_1']
        
        hex_count = macro.get('hexstrings', 0)
        if hex_count > 4:
            current_score += MACRO_LOGIC_SCORES['hex_max_score']
        else:
            current_score += hex_count  
        
        if macro.get('iocs', 0) > 0:
            current_score += MACRO_LOGIC_SCORES['has_iocs']
        if macro.get('base64strings', 0) > 0:
            current_score += MACRO_LOGIC_SCORES['has_base64']
        if macro.get('dridexstrings', 0) > 0:
            current_score += MACRO_LOGIC_SCORES['has_dridex']
        
        if current_score > total_macro_score:
            total_macro_score = current_score

    if total_macro_score < 2:
        console.print(f"[dim]\\[check_macros][/dim] Result: Macros safe | Added score: [green]+{total_macro_score}[/green]")
        return ATTACHMENT_SCORES['macro_risk_low']
    elif total_macro_score < 5:
        console.print(f"[dim]\\[check_macros][/dim] Result: Macros suspicious | Added score: [orange1]+{total_macro_score}[/orange1]")
        return ATTACHMENT_SCORES['macro_risk_medium']
    else:
        console.print(f"[dim]\\[check_macros][/dim] Result: Macros detected | Added score: [red]+{total_macro_score}[/red]")
        return ATTACHMENT_SCORES['macro_risk_high']
