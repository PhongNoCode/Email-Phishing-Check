"""Module containing static analysis logic, scoring, and multithreaded API calls."""

import threading
import time
import concurrent.futures
from core.utils import api  
from core.email_analyzer import parsers
from rich.console import Console
from core.email_analyzer.constants import MACRO_DANGEROUS_KEYWORDS
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
        self.total_score = 0

    def check_from_vs_return_path(self):
        """Compare the domains of the From and Return-Path fields in the Header.

        Returns:
            int: The risk score (+15 for mismatch, +0 for match or missing data).
        """
        if 'email_domain_from' in self.header and 'email_domain_return_path' in self.header:
            if self.header['email_domain_from'] != self.header['email_domain_return_path']:
                console.print("[dim]\\[check_from_vs_return_path][/dim] Result: Mismatch detected | Added score: [red]+15[/red]")
                return 10
            else:
                console.print("[dim]\\[check_from_vs_return_path][/dim] Result: Domains match | Added score: [green]+0[/green]")
                return 0
        else:
            console.print("[dim]\\[check_from_vs_return_path][/dim] Result: Header keys missing | Added score: [green]+0[/green]")
            return 0

    def check_from_vs_reply_to(self):
        """Compare the domains of the From and Reply-To fields in the Header.

        Returns:
            int: The risk score (+10 for mismatch, +0 for match).
        """
        if 'email_domain_from' in self.header and 'email_domain_reply_to' in self.header:
            if self.header['email_domain_from'] != self.header['email_domain_reply_to']:
                console.print("[dim]\\[check_from_vs_reply_to][/dim] Result: Mismatch detected | Added score: [red]+10[/red]")
                return 5
            else:
                console.print("[dim]\\[check_from_vs_reply_to][/dim] Result: Domains match | Added score: [green]+0[/green]")
                return 0
        return 0

    def check_from_vs_message_id(self):
        """Compare the domains of the Message-ID and From fields.

        Returns:
            int: The risk score (+5 for mismatch, +0 for match).
        """
        if 'email_domain_message_id' in self.route and 'email_domain_from' in self.header:
            if self.route['email_domain_message_id'] != self.header['email_domain_from']:
                console.print("[dim]\\[check_from_vs_message_id][/dim] Result: Mismatch detected | Added score: [red]+5[/red]")
                return 5
            else:
                console.print("[dim]\\[check_from_vs_message_id][/dim] Result: Domains match | Added score: [green]+0[/green]")
                return 0
        return 0

    def check_dkim_signature(self):
        """Check if the DKIM signature is marked as failed/invalid.

        Returns:
            int: The risk score (+15 if DKIM failed, +0 if valid or missing).
        """
        if 'dkim_signature' in self.header:
            if self.header['dkim_signature'] == True:
                console.print("[dim]\\[check_dkim_signature][/dim] Result: Invalid signature | Added score: [red]+15[/red]")
                return 10
            else:
                console.print("[dim]\\[check_dkim_signature][/dim] Result: Valid signature | Added score: [green]+0[/green]")
                return 0
        else:
            console.print("[dim]\\[check_dkim_signature][/dim] Result: Header key missing | Added score: [green]+0[/green]")
            return 0

    def check_spf(self):
        """Evaluate the SPF protocol result.

        Returns:
            int: The risk score (+10 if SPF failed, +0 if safe or missing).
        """
        if 'receive_spf' in self.header:
            if self.header['receive_spf'] == True:
                console.print("[dim]\\[check_spf][/dim] Result: Invalid SPF | Added score: [red]+10[/red]")
                return 10
            else:
                console.print("[dim]\\[check_spf][/dim] Result: Valid SPF | Added score: [green]+0[/green]")
                return 0
        else:
            console.print("[dim]\\[check_spf][/dim] Result: Header key missing | Added score: [green]+0[/green]")
            return 0

    def check_attachment_hashes(self):
        """Check attachment hashes via an external API with rate limiting.

        Returns:
            int: The risk score based on API evaluation (+100 for high risk, +0 for safe).
        """
        if not self.hash_of_file:
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
                    console.print("[dim]\\[check_attachment_hashes][/dim] Result: High malicious score | Added score: [bold red]+100[/bold red]")
                    hash_cache[file_hash] = 100
                    return 100
                    
                else:
                    console.print("[dim]\\[check_attachment_hashes][/dim] Result: Low/No malicious score | Added score: [green]+0[/green]")
                    hash_cache[file_hash] = 0
                    return 0  
            except Exception as e:
                console.print(f"[dim]\\[check_attachment_hashes][/dim] Result: Hash not found in VT database for {file_name} | Added score: [green]+0[/green]")
                hash_cache[file_hash] = 0
        return 0
            
    def check_file_extensions(self):
        """Check the risk score based on the file extension.

        Returns:
            int: The risk score dependent on the attachment type (+25, +15, or +0).
        """
        if not self.ext:
            return 0
            
        highest_score = sorted(self.ext.values())[0]
        if highest_score == 0:
            console.print("[dim]\\[check_file_extensions][/dim] Result: Score detected | Added score: [red]+25[/red]")
            return 15
        elif highest_score == 1:
            console.print("[dim]\\[check_file_extensions][/dim] Result: Score detected | Added score: [orange1]+15[/orange1]")
            return 5
        else: 
            console.print("[dim]\\[check_file_extensions][/dim] Result: Score detected | Added score: [green]+0[/green]")
            return 0

    def check_urls(self):
        """Check URLs to detect suspicious links based on predetermined risk levels.

        Returns:
            int: The risk score (+10 for raw IPs, +5 for URL shorteners).
        """
        if not self.url:
            return 0
            
        highest_score = sorted(self.url.values())[0]
        if highest_score == 0:
            console.print("[dim]\\[check_urls][/dim] Result: Score detected | Added score: [red]+10[/red]")
            return 10
        elif highest_score == 1:
            console.print("[dim]\\[check_urls][/dim] Result: Score detected | Added score: [orange]+5[/orange]")
            return 5
        else:
            console.print("[dim]\\[check_urls][/dim] Result: Score detected | Added score: [green]+0[/green]")
            return 0

    def check_urgent_headers(self):
        """Check for the presence of urgent headers in the email content.

        Returns:
            int: The risk score (+10 for detected urgent headers, +0 for none).
        """
        if not self.urgent_headers:
            return 0
            
        console.print("[dim]\\[check_urgent_headers][/dim] Result: Urgent headers detected | Added score: [red]+10[/red]")
        return 10

    def check_macros(self):
        """Check for the presence of macros in email attachments.

        Returns:
            int: The risk score (+25 for detected macros, +15 for suspicious, 0 for none).
        """
        total_macro_score = 0
        for macro in self.macro_analysis:

            autoexec_kw = macro.get('autoexec_keywords', [])
            suspicious_kw = macro.get('suspicious_keywords', [])
            patterns = macro.get('patterns', [])

            if (len(autoexec_kw) > 0 and len(suspicious_kw) > 0) or (len(patterns) > 0):
                console.print("[dim]\\[check_macros][/dim] Result: Macros detected | Added score: [red]+25[/red]")
                return 25
            
            for word in suspicious_kw:
                kw = word.split(':')[1].strip()
                if kw in MACRO_DANGEROUS_KEYWORDS:
                    console.print("[dim]\\[check_macros][/dim] Result: Macros detected | Added score: [red]+25[/red]")
                    return 25

            current_score = 0
            if macro.get('suspicious', 0) > 0:
                current_score += 3

            if len(autoexec_kw) > 1:
                current_score += 6
            elif len(autoexec_kw) == 1:
                current_score += 3

            if len(suspicious_kw) > 1:
                current_score += 6
            elif len(suspicious_kw) == 1:
                current_score += 4

            
            if len(patterns) > 1:
                current_score += 6
            elif len(patterns) == 1:
                current_score += 4

            
            hex_count = macro.get('hexstrings', 0)
            if hex_count > 4:
                current_score += 4
            else:
                current_score += hex_count  

            
            if macro.get('iocs', 0) > 0:
                current_score += 3
            if macro.get('base64strings', 0) > 0:
                current_score += 2
            if macro.get('dridexstrings', 0) > 0:
                current_score += 4

            
            if current_score > total_macro_score:
                total_macro_score = current_score

        if total_macro_score < 2:
            console.print(f"[dim]\\[check_macros][/dim] Result: Macros safe | Added score: [green]+{total_macro_score}[/green]")
            return 0
        elif total_macro_score < 5:
            console.print(f"[dim]\\[check_macros][/dim] Result: Macros suspicious | Added score: [orange1]+{total_macro_score}[/orange1]")
            return 15
        else:
            console.print(f"[dim]\\[check_macros][/dim] Result: Macros detected | Added score: [red]+{total_macro_score}[/red]")
            return 25

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
                executor.submit(self.check_macros)
            ]
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result is not None:
                    self.total_score += result