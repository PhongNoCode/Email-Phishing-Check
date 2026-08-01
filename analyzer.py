"""Module containing static analysis logic, scoring, and multithreaded API calls."""

import threading
import time
import concurrent.futures
import API
import parsers

hash_cache = {}
api_lock = threading.Lock()
api_call_times = []

class static_analyze():
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
        self.total_score = 0

    def from_vs_return_path(self):
        """Compare the domains of the From and Return-Path fields in the Header.

        Returns:
            int: The risk score (+15 for mismatch, +0 for match or missing data).
        """
        if 'email_domain_from' in self.header and 'email_domain_return_path' in self.header:
            if self.header['email_domain_from'] != self.header['email_domain_return_path']:
                print("[from_vs_return_path] Result: Mismatch detected | Added score: +15")
                return 15
            else:
                print("[from_vs_return_path] Result: Domains match | Added score: +0")
                return 0
        else:
            print("[from_vs_return_path] Result: Header keys missing | Added score: +0")
            return 0

    def from_vs_reply_to(self):
        """Compare the domains of the From and Reply-To fields in the Header.

        Returns:
            int: The risk score (+10 for mismatch, +0 for match).
        """
        if self.header['email_domain_from'] != self.header['email_domain_reply_to']:
            print("[from_vs_reply_to] Result: Mismatch detected | Added score: +10")
            return 10
        else:
            print("[from_vs_reply_to] Result: Domains match | Added score: +0")
            return 0

    def from_vs_message_id(self):
        """Compare the domains of the Message-ID and From fields.

        Returns:
            int: The risk score (+5 for mismatch, +0 for match).
        """
        if self.route['email_domain_message_id'] != self.header['email_domain_from']:
            print("[from_vs_message_id] Result: Mismatch detected | Added score: +5")
            return 5
        else:
            print("[from_vs_message_id] Result: Domains match | Added score: +0")
            return 0

    def dkim_signature(self):
        """Check if the DKIM signature is marked as failed/invalid.

        Returns:
            int: The risk score (+15 if DKIM failed, +0 if valid or missing).
        """
        if 'dkim_signature' in self.header:
            if self.header['dkim_signature'] == True:
                print("[dkim_signature] Result: Valid signature | Added score: +15")
                return 15
            else:
                print("[dkim_signature] Result: Invalid signature | Added score: +0")
                return 0
        else:
            print("[dkim_signature] Result: Header key missing | Added score: +0")
            return 0

    def spf(self):
        """Evaluate the SPF protocol result.

        Returns:
            int: The risk score (+10 if SPF failed, +0 if safe or missing).
        """
        if 'receive_spf' in self.header:
            if self.header['receive_spf'] == True:
                print("[spf] Result: Valid SPF | Added score: +10")
                return 10
            else:
                print("[spf] Result: Invalid SPF | Added score: +0")
                return 0
        else:
            print("[spf] Result: Header key missing | Added score: +0")
            return 0

    def check_hash(self):
        """Check attachment hashes via an external API with rate limiting.

        Returns:
            int: The risk score based on API evaluation (+100 for high risk, +0 for safe).
        """
        if not self.hash_of_file:
            return 0
        # Review each hash of a file if an email has more than one hash
        for file_name, file_hash in self.hash_of_file.items():
            if file_hash in hash_cache:
                print(f"[check_hash] Result: Get in hash cache | Add score: +{hash_cache[file_hash]}")
                return hash_cache[file_hash]

        # Auto lock when start and release when finish
        with api_lock:
            if len(api_call_times) == 4:
                current_time = time.time()
                if current_time - api_call_times[0] <= 60 :
                    time.sleep(60 - (current_time - api_call_times[0]) + 0.5)
                api_call_times.pop(0)
            api_call_times.append(time.time())
            
        for res in self.hash_of_file.items():
            try:
                result = API.check_hash(res)
            
                if result['malicious'] >= 4:
                    print("[check_hash] Result: High malicious score | Added score: +100")
                    hash_cache[self.hash_of_file] = 100
                    return 100
                    
                else:
                    print("[check_hash] Result: Low/No malicious score | Added score: +0")
                    hash_cache[self.hash_of_file] = 0
                    return 0  
            except Exception as e:
                print(f"[check_hash] Result: Hash not found in VT database for {file_name} | Added score: +0")
                hash_cache[file_hash] = 0
                return 0
            
    def check_extension(self):
        """Check the risk score based on the file extension.

        Returns:
            int: The risk score dependent on the attachment type (+25, +15, or +0).
        """
        if not self.ext:
            return 0
            
        highest_score = sorted(self.ext.values())[0]
        if highest_score == 0:
            print("[check_extension] Result: Score 0 detected | Added score: +25")
            return 25
        elif highest_score == 1:
            print("[check_extension] Result: Score 1 detected | Added score: +15")
            return 15
        else: 
            print("[check_extension] Result: Score > 1 detected | Added score: +0")
            return 0

    def check_url(self):
        """Check URLs to detect suspicious links based on predetermined risk levels.

        Returns:
            int: The risk score (+10 for raw IPs, +5 for URL shorteners).
        """
        if not self.url:
            return 0
            
        highest_score = sorted(self.url.values())[0]
        if highest_score == 0:
            print("[check_url] Result: Score 0 detected | Added score: +10")
            return 10
        elif highest_score == 1:
            print("[check_url] Result: Score 1 detected | Added score: +5")
            return 5
        else:
            print("[check_url] Result: Score > 1 detected | Added score: +0")
            return 0

    def runall(self):  
        """Execute all checks concurrently using a ThreadPoolExecutor.

        Note:
            Share Memory By Communicating.
        """
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            futures = [
                executor.submit(self.from_vs_return_path),
                executor.submit(self.from_vs_reply_to),
                executor.submit(self.dkim_signature),
                executor.submit(self.from_vs_message_id),
                executor.submit(self.spf),
                executor.submit(self.check_hash),
                executor.submit(self.check_extension),
                executor.submit(self.check_url)
            ]
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result is not None:
                    self.total_score += result