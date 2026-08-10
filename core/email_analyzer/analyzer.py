"""Module containing static analysis logic, scoring, and multithreaded API calls."""

import threading
import time
import concurrent.futures
from core.utils import api  
from core.email_analyzer import parsers
from rich.console import Console
from core.email_analyzer.constants import MACRO_DANGEROUS_KEYWORDS
from core.email_analyzer.risk_policy import AUTHENTICATION_SCORES, HEADER_SCORES, URL_SCORES, ATTACHMENT_SCORES, MACRO_LOGIC_SCORES, IDENTITY_SCORES
hash_cache = {}
api_lock = threading.Lock()
api_call_times = []
console = Console()

class StaticAnalyzer:
    """Class to perform static analysis on an email file."""

    def __init__(self, email_file):
        """Initialize the analysis object for a specific email file.

        Args:
            email_file (str): The file path to the .eml file to be analyzed.
        """
        self.email = email_file
        self.header = parsers.analyze_header(email_file)
        self.route = parsers.analyze_route(email_file)
        self.ext = parsers.analyze_extension(email_file)
        self.url = parsers.analyze_link_urls(email_file)
        self.subject = parsers.analyze_subject(email_file)
        self.hash_of_file = parsers.analyze_attachment(email_file)
        self.urgent_headers = parsers.analyze_urgent_headers(email_file)
        self.macro_analysis = parsers.analyze_email_macros(email_file)
        self.homoglyph = parsers.analyze_homoglyph(self.header, self.url)

        self.total_score = 0

    def check_from_vs_return_path(self):
        """Compare the domains of the From and Return-Path fields in the Header.

        Returns:
            int: The risk score.
        """
        if 'email_domain_from' in self.header and 'email_domain_return_path' in self.header:
            if self.header['email_domain_from'] != self.header['email_domain_return_path']:
                console.print(f"[dim]\\[check_from_vs_return_path][/dim] Result: Mismatch detected | Added score: [red]+{AUTHENTICATION_SCORES['from_vs_return_path']}[/red]")
                return AUTHENTICATION_SCORES['from_vs_return_path']
            else:
                console.print("[dim]\\[check_from_vs_return_path][/dim] Result: Domains match | Added score: [green]+0[/green]")
                return 0
        else:
            console.print("[dim]\\[check_from_vs_return_path][/dim] Result: Header keys missing | Added score: [green]+0[/green]")
            return 0

    def check_from_vs_reply_to(self):
        """Compare the domains of the From and Reply-To fields in the Header.

        Returns:
            int: The risk score.
        """
        if 'email_domain_from' in self.header and 'email_domain_reply_to' in self.header:
            if self.header['email_domain_from'] != self.header['email_domain_reply_to']:
                console.print(f"[dim]\\[check_from_vs_reply_to][/dim] Result: Mismatch detected | Added score: [red]+{AUTHENTICATION_SCORES['from_vs_reply_to']}[/red]")
                return AUTHENTICATION_SCORES['from_vs_reply_to']
            else:
                console.print("[dim]\\[check_from_vs_reply_to][/dim] Result: Domains match | Added score: [green]+0[/green]")
                return 0
        console.print("[dim]\\[check_from_vs_reply_to][/dim] Result: Evident is not clear | Added score: [green]+0[/green]")
        return 0

    def check_from_vs_message_id(self):
        """Compare the domains of the Message-ID and From fields.

        Returns:
            int: The risk score.
        """
        if 'email_domain_message_id' in self.route and 'email_domain_from' in self.header:
            if self.route['email_domain_message_id'] != self.header['email_domain_from']:
                console.print(f"[dim]\\[check_from_vs_message_id][/dim] Result: Mismatch detected | Added score: [red]+{AUTHENTICATION_SCORES['from_vs_message_id']}[/red]")
                return AUTHENTICATION_SCORES['from_vs_message_id']
            else:
                console.print("[dim]\\[check_from_vs_message_id][/dim] Result: Domains match | Added score: [green]+0[/green]")
                return 0
        console.print(f"[dim]\\[email_domain_message_id][/dim] Result: Evident is not clear | Added score: [green]+0[/green]")
        return 0

    def check_dkim_signature(self):
        """Check if the DKIM signature is marked as failed/invalid.

        Returns:
            int: The risk score 
        """
        if 'dkim_signature' in self.header:
            if self.header['dkim_signature'] == True:
                console.print(f"[dim]\\[check_dkim_signature][/dim] Result: Invalid signature | Added score: [red]+{AUTHENTICATION_SCORES['fail_dkim']}[/red]")
                return AUTHENTICATION_SCORES['fail_dkim']
            else:
                console.print("[dim]\\[check_dkim_signature][/dim] Result: Valid signature | Added score: [green]+0[/green]")
                return 0
        else:
            console.print("[dim]\\[check_dkim_signature][/dim] Result: Header key missing | Added score: [green]+0[/green]")
            return 0

    def check_spf(self):
        """Evaluate the SPF protocol result.

        Returns:
            int: The risk score.
        """
        if 'receive_spf' in self.header:
            if self.header['receive_spf'] == True:
                console.print(f"[dim]\\[check_spf][/dim] Result: Invalid SPF | Added score: [red]+{AUTHENTICATION_SCORES['not_pass_spf']}[/red]")
                return AUTHENTICATION_SCORES['not_pass_spf']
            else:
                console.print("[dim]\\[check_spf][/dim] Result: Valid SPF | Added score: [green]+0[/green]")
                return 0
        else:
            console.print("[dim]\\[check_spf][/dim] Result: Header key missing | Added score: [green]+0[/green]")
            return 0

    def check_attachment_hashes(self):
        """Check attachment hashes via an external API with rate limiting.

        Returns:
            int: The risk score based on API evaluation.
        """
        if not self.hash_of_file:
            console.print(f"[dim]\\[check_attachment_hashes][/dim] Result: No hash found in email | Added score: [green]+0[/green]")
            return 0
            
        # Review each hash of a file if an email has more than one hash
        for file_name, file_hash in self.hash_of_file.items():
            if file_hash in hash_cache:
                console.print(f"[dim]\\[check_attachment_hashes][/dim] Result: Get in hash cache | Add score: [yellow]+{hash_cache[file_hash]}[/yellow]")
                return hash_cache[file_hash]

        # Auto lock when start and release when finish
        with api_lock:
            if len(api_call_times) == 4:
                current_time = time.time()
                if current_time - api_call_times[0] <= 60 :
                    time.sleep(60 - (current_time - api_call_times[0]) + 0.5)
                api_call_times.pop(0)
            api_call_times.append(time.time())
            
        for hash_entry in self.hash_of_file.items():
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
            
    def check_file_extensions(self):
        """Check the risk score based on the file extension.

        Returns:
            int: The risk score dependent on the attachment type.
        """
        if not self.ext:
            console.print("[dim]\\[check_file_extensions][/dim] Result: No attachment | Added score: [green]+0[/green]")
            return 0
            
        highest_score = sorted(self.ext.values())[0]
        if highest_score == 0:
            console.print(f"[dim]\\[check_file_extensions][/dim] Result: Mismatch extension from mail and file | Added score: [red]+{ATTACHMENT_SCORES['ext_mismatch']}[/red]")
            return ATTACHMENT_SCORES['ext_mismatch']
        elif highest_score == 1:
            console.print(f"[dim]\\[check_file_extensions][/dim] Result: Dangerous extension | Added score: [orange1]+{ATTACHMENT_SCORES['dangerous_ext']}[/orange1]")
            return ATTACHMENT_SCORES['dangerous_ext']
        else: 
            console.print("[dim]\\[check_file_extensions][/dim] Result: Extension is clear | Added score: [green]+0[/green]")
            return 0

    def check_urls(self):
        """Check URLs to detect suspicious links based on predetermined risk levels.

        Returns:
            int: The risk score.
        """
        if not self.url:
            console.print("[dim]\\[check_urls][/dim] Result: No URL | Added score: [green]+0[/green]")
            return 0
            
        highest_score = sorted(self.url.values())[0]
        if highest_score == 0:
            console.print(f"[dim]\\[check_urls][/dim] Result: Raw IP detected | Added score: [red]+{URL_SCORES['raw_ip']}[/red]")
            return URL_SCORES['raw_ip']
        elif highest_score == 1:
            console.print(f"[dim]\\[check_urls][/dim] Result: Shortened IP detected | Added score: [orange]+{URL_SCORES['shortened']}[/orange]")
            return URL_SCORES['shortened']
        else:
            console.print(f"[dim]\\[check_urls][/dim] Result: URLs is clean | Added score: [green]+0[/green]")
            return 0

    def check_urgent_headers(self):
        """Check for the presence of urgent headers in the email content.

        Returns:
            int: The risk score.
        """
        if not self.urgent_headers:
            console.print(f"[dim]\\[check_urgent_headers][/dim] Result: Safe header | Added score: [green]+0[/green]")
            return 0
            
        console.print(f"[dim]\\[check_urgent_headers][/dim] Result: Urgent headers detected | Added score: [red]+{HEADER_SCORES['urgent_header']}[/red]")
        return HEADER_SCORES['urgent_header']

    def check_macros(self):
        """Check for the presence of macros in email attachments.

        Returns:
            int: The risk score.
        """
        total_macro_score = 0
        for macro in self.macro_analysis:

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

    def check_homoglyph(self):
        total_score_homo = 0
        if self.homoglyph['homoglyph_from'] == 1:
            total_score_homo += IDENTITY_SCORES['homoglyph_from']
            console.print(f"[dim]\\[check_homoglyph][/dim] Result: Homoglyph of from suspicious | Added score: [red]+{IDENTITY_SCORES['homoglyph_from']}[/red]")
        else:
            console.print(f"[dim]\\[check_homoglyph][/dim] Result: Homoglyph of from clean | Added score: [green]+0[/green]")

        
        if self.homoglyph['homoglyph_reply_to'] == 1:
            total_score_homo += IDENTITY_SCORES['homoglyph_reply_to']
            console.print(f"[dim]\\[check_homoglyph][/dim] Result: Homoglyph of reply to suspicious | Added score: [orange1]+{IDENTITY_SCORES['homoglyph_reply_to']}[/orange1]")
        else:
            console.print(f"[dim]\\[check_homoglyph][/dim] Result: Homoglyph of reply to clean | Added score: [green]+0[/green]")

        if self.homoglyph['homoglyph_return_path'] == 1:
            total_score_homo += IDENTITY_SCORES['homoglyph_return_path']
            console.print(f"[dim]\\[check_homoglyph][/dim] Result: Homoglyph of return path suspicious | Added score: [orange1]+{IDENTITY_SCORES['homoglyph_return_path']}[/orange1]")
        else:
            console.print(f"[dim]\\[check_homoglyph][/dim] Result: Homoglyph of return path clean | Added score: [green]+0[/green]")

        if self.homoglyph['homoglyph_url'] == 1:
            total_score_homo += IDENTITY_SCORES['homoglyph_url']
            console.print(f"[dim]\\[check_homoglyph][/dim] Result: Homoglyph of url suspicious | Added score: [red]+{IDENTITY_SCORES['homoglyph_url']}[/red]")
        else:
            console.print(f"[dim]\\[check_homoglyph][/dim] Result: Homoglyph of url clean | Added score: [green]+0[/green]")

    def run_all(self):  
        """Execute all checks concurrently using a ThreadPoolExecutor.

        Note:
            Share Memory By Communicating.
        """
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            futures = [
                executor.submit(self.check_from_vs_return_path),
                executor.submit(self.check_from_vs_reply_to),
                executor.submit(self.check_dkim_signature),
                executor.submit(self.check_from_vs_message_id),
                executor.submit(self.check_spf),
                executor.submit(self.check_attachment_hashes),
                executor.submit(self.check_file_extensions),
                executor.submit(self.check_urls),
                executor.submit(self.check_urgent_headers),
                executor.submit(self.check_macros),
                executor.submit(self.check_homoglyph)
            ]
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result is not None:
                    self.total_score += result
