"""Module containing static analysis logic, scoring, and multithreaded API calls."""

import concurrent.futures
from rich.console import Console
import email
from core.email_analyzer.modules import authentication
from core.email_analyzer.modules import attachment
from core.email_analyzer.modules import identity
from core.email_analyzer.modules import url
from core.email_analyzer.modules import body
from core.email_analyzer.modules import header as header_module
from core.ast_analyzer.main_ast import analyze_python_files
from core.parsers import *
console = Console()

class StaticAnalyzer:
    """Class to perform static analysis on an email file."""

    def __init__(self, email_file_path):
        """Initialize the analysis object for a specific email file."""
        self.email_file_path = email_file_path
        

        with open(email_file_path, 'rb') as f:
            self.email_message = email.message_from_binary_file(f)
            
        
        raw_email_text = self.email_message.as_string().lower()

        
        self.header = analyze_header(self.email_message)
        self.route = analyze_route(self.email_message)
        self.subject = analyze_subject(self.email_message)
        self.urgent_headers = analyze_urgent_headers(raw_email_text)
        passwords = analyze_potential_passwords(raw_email_text)
        self.extracted_files = analyze_universal_extract(self.email_message, passwords)
        
        self.ext = analyze_extension(self.extracted_files) 
        self.url = analyze_link_urls(raw_email_text)
        self.hash_of_file = analyze_attachment(self.extracted_files)
        self.macro_analysis = analyze_email_macros(self.extracted_files)
        self.pdf = analyze_pdf(self.extracted_files)

        self.body_content = analyze_body_content(self.email_message)
        self.urgent_body_content = analyze_urgent_body_content(self.body_content)
        self.homoglyph = analyze_homoglyph(self.header, self.url)
        self.typo = analyze_typo(self.header, self.url)

        self.ast_analysis = analyze_python_files(self.extracted_files)
        
        self.total_score = 0

    # Header
    def check_from_vs_return_path(self):
        return authentication.check_from_vs_return_path(self.header)

    def check_from_vs_reply_to(self):
        return authentication.check_from_vs_reply_to(self.header)

    def check_from_vs_message_id(self):
        return authentication.check_from_vs_message_id(self.route, self.header)

    def check_dkim_signature(self):
        return authentication.check_dkim_signature(self.header)

    def check_spf(self):
        return authentication.check_spf(self.header)

    # Attachments
    def check_attachment_hashes(self):
        return attachment.check_attachment_hashes(self.hash_of_file)
            
    def check_file_extensions(self):
        return attachment.check_file_extensions(self.ext)

    def check_macros(self):
        return attachment.check_macros(self.macro_analysis)

    # URLs
    def check_urls(self):
        return url.check_urls(self.url)

    # Special
    def check_urgent_headers(self):
        return header_module.check_urgent_headers(self.urgent_headers)

    def check_homoglyph(self):
        return identity.check_homoglyph(self.homoglyph)

    def check_typo(self):
        return identity.check_typo(self.typo)

    def check_body_content(self):
        return body.check_urgent_body(self.urgent_body_content)

    def run_all(self):  
        """Execute all checks concurrently using a ThreadPoolExecutor."""
        with concurrent.futures.ThreadPoolExecutor(max_workers=12) as executor:
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
                executor.submit(self.check_homoglyph),
                executor.submit(self.check_typo),
                executor.submit(self.check_body_content)
            ]
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result is not None:
                    self.total_score += result



