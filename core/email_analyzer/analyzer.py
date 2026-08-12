"""Module containing static analysis logic, scoring, and multithreaded API calls."""

import concurrent.futures
from core.email_analyzer import parsers
from rich.console import Console


from core.email_analyzer.modules import authentication
from core.email_analyzer.modules import attachment
from core.email_analyzer.modules import url as url_module
from core.email_analyzer.modules import header as header_module
from core.email_analyzer.modules import image 

console = Console()

class StaticAnalyzer:
    """Class to perform static analysis on an email file."""

    def __init__(self, email_file):
        """Initialize the analysis object for a specific email file."""
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
        return authentication.check_from_vs_return_path(self.header)

    def check_from_vs_reply_to(self):
        return authentication.check_from_vs_reply_to(self.header)

    def check_from_vs_message_id(self):
        return authentication.check_from_vs_message_id(self.route, self.header)

    def check_dkim_signature(self):
        return authentication.check_dkim_signature(self.header)

    def check_spf(self):
        return authentication.check_spf(self.header)

    
    def check_attachment_hashes(self):
        return attachment.check_attachment_hashes(self.hash_of_file)
            
    def check_file_extensions(self):
        return attachment.check_file_extensions(self.ext)

    def check_macros(self):
        return attachment.check_macros(self.macro_analysis)

   
    def check_urls(self):
        return url_module.check_urls(self.url)

    
    def check_urgent_headers(self):
        return header_module.check_urgent_headers(self.urgent_headers)

    def check_homoglyph(self):
        
        return header_module.check_homoglyph(self.homoglyph)

    def run_all(self):  
        """Execute all checks concurrently using a ThreadPoolExecutor."""
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
