"""Module containing functions to read, parse, and extract data from email (.eml) files."""

import re
import email
import hashlib
import tldextract
from core.email_analyzer.constants import DANGEROUS_CONTENT_TYPES, PHISHING_EMAIL_KEYWORDS
import ahocorasick
import email
from oletools.olevba import VBA_Parser, detect_autoexec, detect_suspicious, detect_patterns
import zipfile
from oletools import rtfobj 

def extract_domain(line):
    """Extract the domain name from a string containing an email address.

    Args:
        line (str): The text line containing the email address.

    Returns:
        str: The extracted domain name.
    """
    extracted_info = tldextract.extract("".join(re.findall(r'@[^>]*', line)))
    return extracted_info.domain

def analyze_header(email_file_path):
    """Analyze the email Header to extract From, Return-Path, Reply-To, SPF, and DKIM information.

    Args:
        email_file_path (str): The file path to the .eml file.

    Returns:
        dict: A dictionary containing the extracted header information.
    """
    with open(email_file_path, 'r', encoding='utf-8') as email_file:
        email_lines = email_file.readlines()   
        
    header_data = {}
    for line in email_lines:

        if line.startswith('From'):
            display_name_from = "".join(re.findall(r'\s[^\n<.>]*', line)).strip()       
            header_data['email_domain_from'] = extract_domain(line) 

        if line.startswith('Return-Path'):
            header_data['email_domain_return_path'] = extract_domain(line)

        if line.startswith('Reply-To'):
            header_data['email_domain_reply_to'] = extract_domain(line)

        if line.startswith('Received-SPF'):
            for status in ['Fail', 'SoftFail', 'Neutral']:
                if status in line:
                    header_data['receive_spf'] = True
                    break

        if line.startswith('dkim_signature'):
            if 'Fail' in line:
                header_data['dkim_signature'] = True

        if line.startswith('Message-ID'):
            header_data['message-id'] = line[12:].strip()

        if line.startswith('Delivered-To'):
            header_data['delivered-to'] = line[13:].strip()

        if line.startswith('From'):
            header_data['from'] = line[6:].strip()

        if line.startswith('To'):
            header_data['to'] = line[4:].strip()

    return header_data


def analyze_content(email_file_path):
    """Analyze the email routing and Message-ID.
    
    Args:
        email_file_path (str): The file path to the .eml file.

    Returns:
        dict: A dictionary containing the content of an email.
    """
    with open(email_file_path, 'rb') as email_file:
        email_message = email.message_from_binary_file(email_file)
        
    content_data = {}
    for part in email_message.walk():
        if part.get_content_type() == 'text/plain':
            raw_payload = part.get_payload(decode=True)
            charset = part.get_content_charset() or 'utf-8'
            content_data['content'] = raw_payload.decode(charset, errors='replace')
            break
            
    return content_data

def analyze_route(email_file_path):
    """Analyze the email routing and Message-ID.

    Args:
        email_file_path (str): The file path to the .eml file.

    Returns:
        dict: A dictionary containing the IPv4 address and Message-ID domain.
    """
    with open(email_file_path, 'r', encoding='utf-8') as email_file:
        email_lines = email_file.readlines()
        
    route_data = {}
    for line in email_lines:
        if line.startswith('Received:'):
            route_data['ipv4'] = "".join(re.findall(r'\[(.*)\]', line))
        if line.startswith('Message-ID'):
            route_data['email_domain_message_id'] = extract_domain(line)
            
    return route_data    

def analyze_link_urls(email_file_path):
    """Extract and perform preliminary risk assessment of URLs found in the email.

    Args:
        email_file_path (str): The file path to the .eml file.

    Returns:
        dict: A dictionary where the key is the URL and the value is the suspicious score 
              (0 for raw IPs, 1 for shortened URLs).
    """
    with open(email_file_path, 'r', encoding='utf-8') as email_file:
        full_email_text = "".join(email_file.readlines())
        
    # Refer to https://stackoverflow.com/questions/49654499/python-extract-urls-from-email-messages
    regex_find_url = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
    urls = re.findall(regex_find_url, full_email_text)
    pattern_ip_numbers = r'http[s]?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'  
    
    url_risk_scores = {}

    for url in urls:
        if re.match(pattern_ip_numbers, url):
            url_risk_scores[url] = 0
            
        for shortener in ['bit.ly', 'tinyurl.com', 'cutt.ly']:
            if shortener in url:
                url_risk_scores[url] = 1                    
                
    return url_risk_scores

def analyze_subject(email_file_path):
    """Extract the subject of the email.

    Args:
        email_file_path (str): The file path to the .eml file.

    Returns:
        dict: A dictionary containing the email subject content.
    """
    with open(email_file_path, 'r', encoding='utf-8') as email_file:
        email_lines = email_file.readlines()
        
    subject_data = {}
    for line in email_lines:
        if line.startswith('Subject'):
            subject_data['subject'] = line[8:].strip()
            
    return subject_data

def analyze_urgent_headers(email_file_path):
    """Analyze the email content for urgent headers using the Aho-Corasick algorithm.

    Args:
        email_file_path (str): The file path to the .eml file.

    Returns:
            dict: A dictionary containing the email urgent headers.
    """
    
    automaton = ahocorasick.Automaton()
    urgent_headers = {}
    list_of_urgent_headers = []
    with open(email_file_path, 'r') as file:
        haystack = "".join(file.readlines()).lower()
        for idx, key in enumerate(PHISHING_EMAIL_KEYWORDS):
            automaton.add_word(key, (idx, key))
        automaton.make_automaton()
        for end_index, (insert_order, original_value) in automaton.iter(haystack):
            start_index = end_index - len(original_value) + 1
            list_of_urgent_headers.append(original_value)
            assert haystack[start_index:start_index + len(original_value)] == original_value
    urgent_headers['urgent_headers'] = list_of_urgent_headers

    return urgent_headers

def analyze_attachment(email_file_path):
    """Extract attachments and calculate their SHA256 hashes.

    Args:
        email_file_path (str): The file path to the .eml file.

    Returns:
        dict: A dictionary where the key is the attachment filename and the value is its SHA256 hash.
    """
    with open(email_file_path, 'rb') as email_file:
        email_message = email.message_from_binary_file(email_file)
        
    attachment_hashes = {}
    for part in email_message.walk():
        if part.get_content_disposition() == 'attachment' or part.get_content_disposition() == 'inline':
            file_content = part.get_payload(decode=True)
            sha256_hasher = hashlib.sha256()
            sha256_hasher.update(file_content)
            
            if part.get_filename() != None:
                attachment_hashes[str(part.get_filename())] = sha256_hasher.hexdigest()
                
    return attachment_hashes

def analyze_extension(email_file_path):
    """Check the extension and content_type of attachments for potential threats.

    Args:
        email_file_path (str): The file path to the .eml file.

    Returns:
        dict: A dictionary containing attachment details and their assigned threat score 
              (0 is extremely dangerous, 1 is warning, 2 is normal).
    """
    with open(email_file_path, 'rb') as email_file:
        email_message = email.message_from_binary_file(email_file)
        
    extension_scores = {}
    for part in email_message.walk():       
        file_name = part.get_filename()
        content_type = part.get_content_type()
        
        # 0 is extremely dangerous, 1 is warning, 2 is normal
        if file_name != None and content_type != None:   
            extension = "".join(re.findall(r'(\..*$)', file_name.strip()))
            
            if extension in DANGEROUS_CONTENT_TYPES and content_type not in DANGEROUS_CONTENT_TYPES[extension]:
                extension_scores[file_name + ' ' + extension + ' ' + content_type] = 0
            elif extension in DANGEROUS_CONTENT_TYPES:
                extension_scores[file_name + ' ' + extension + ' ' + content_type] = 1
            else:
                extension_scores[file_name + ' ' + extension + ' ' + content_type] = 2
                
    return extension_scores

def analyze_email_macros(email_file_path):
    """Analyze the email for macros in attachments and extract relevant information."""
    with open(email_file_path, 'rb') as email_file:
            email_message = email.message_from_binary_file(email_file)
    macros = []
    for part in email_message.walk():
        try:
            if part.get_content_disposition() == 'attachment':
                with open(f'./core/outputs/{part.get_filename()}', 'wb') as attachment_file:
                    attachment_file.write(part.get_payload(decode=True))

                attachment_filename = str(part.get_filename())
                attachment_data = open('./core/outputs/'+attachment_filename, 'rb').read()
                vba_parser = VBA_Parser(attachment_filename, data=attachment_data)

                if vba_parser.detect_vba_macros():
                    vba_parser.analyze_macros()
                    for filename, stream_path, vba_filename, vba_code in vba_parser.extract_macros():
                        res_macro = {}
                        res_macro['attachment_name'] = attachment_filename
                        res_macro['vba_filename'] = vba_filename
                        if vba_parser.nb_autoexec > 0:
                            res_macro['autoexec'] = vba_parser.nb_autoexec
                        if vba_parser.nb_suspicious > 0:
                            res_macro['suspicious'] = vba_parser.nb_suspicious
                        if vba_parser.nb_iocs > 0:
                            res_macro['iocs'] = vba_parser.nb_iocs
                        if vba_parser.nb_hexstrings > 0:
                            res_macro['hexstrings'] = vba_parser.nb_hexstrings
                        if vba_parser.nb_base64strings > 0:
                            res_macro['base64strings'] = vba_parser.nb_base64strings
                        if vba_parser.nb_dridexstrings > 0:
                            res_macro['dridexstrings'] = vba_parser.nb_dridexstrings
                        if vba_parser.nb_vbastrings > 0:
                            res_macro['vbastrings'] = vba_parser.nb_vbastrings

                        auto_executable = []
                        autoexec_keywords = detect_autoexec(vba_code)
                        
                        if autoexec_keywords:
                            print('Auto-executable macro keywords found:')
                            for keyword, description in autoexec_keywords:
                                temp_res = '%s: %s' % (keyword, description)
                                auto_executable.append(temp_res)
                        suspicious_keywords = detect_suspicious(vba_code)
                        res_macro['autoexec_keywords'] = auto_executable

                        sus_keywords = []
                        if suspicious_keywords:
                            print('Suspicious VBA keywords found:')
                            for keyword, description in suspicious_keywords:
                                temp_res = '%s: %s' % (keyword, description)
                                sus_keywords.append(temp_res)
                        res_macro['suspicious_keywords'] = sus_keywords

                        patterns = detect_patterns(vba_code)
                        pattern = []
                        if patterns:
                            print('Patterns found:')
                            for pattern_type, value in patterns:
                                temp_res = '%s: %s' % (pattern_type, value)
                                pattern.append(temp_res)
                        res_macro['patterns'] = pattern     
                        macros.append(res_macro)
                    vba_parser.close() 
        except Exception as e:
            print(f"Error processing attachment {part.get_filename()}: {e}")                     
    return macros