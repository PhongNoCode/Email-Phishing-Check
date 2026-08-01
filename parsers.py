"""Module containing functions to read, parse, and extract data from email (.eml) files."""

import re
import email
import hashlib
import tldextract
from constants import DANGEROUS_CONTENT_TYPES

def email_domain(line):
    """Extract the domain name from a string containing an email address.

    Args:
        line (str): The text line containing the email address.

    Returns:
        str: The extracted domain name.
    """
    ext = tldextract.extract("".join(re.findall(r'@[^>]*', line)))
    return ext.domain

def analyze_header(path_to_email):
    """Analyze the email Header to extract From, Return-Path, Reply-To, SPF, and DKIM information.

    Args:
        path_to_email (str): The file path to the .eml file.

    Returns:
        dict: A dictionary containing the extracted header information.
    """
    with open(path_to_email, 'r', encoding='utf-8') as file:
        email_content = file.readlines()
    res = {}
    for line in email_content:

        if line.startswith('From'):
            display_name_from = "".join(re.findall(r'\s[^\n<.>]*', line)).strip()       
            res['email_domain_from'] = email_domain(line) 

        if line.startswith('Return-Path'):
            res['email_domain_return_path'] = email_domain(line)

        if line.startswith('Reply-To'):
            res['email_domain_reply_to'] = email_domain(line)

        if line.startswith('Received-SPF'):
            for status in ['Fail', 'SoftFail', 'Neutral']:
                if status in line:
                    res['receive_spf'] = True
                    break

        if line.startswith('dkim_signature'):
            if 'Fail' in line:
                res['dkim_signature'] = True
    return res

def analyze_route(path_to_email):
    """Analyze the email routing and Message-ID.

    Args:
        path_to_email (str): The file path to the .eml file.

    Returns:
        dict: A dictionary containing the IPv4 address and Message-ID domain.
    """
    with open(path_to_email, 'r', encoding='utf-8') as file:
        email_content = file.readlines()
    ipv4 = ''
    email_domain_message_id = ''
    res = {}
    for line in email_content:
        if line.startswith('Received:'):
            res['ipv4'] = "".join(re.findall(r'\[(.*)\]', line))
        if line.startswith('Message-ID'):
            res['email_domain_message_id'] = email_domain(line)
    return res    

def analyze_link_urls(path_to_email):
    """Extract and perform preliminary risk assessment of URLs found in the email.

    Args:
        path_to_email (str): The file path to the .eml file.

    Returns:
        dict: A dictionary where the key is the URL and the value is the suspicious score 
              (0 for raw IPs, 1 for shortened URLs).
    """
    with open(path_to_email, 'r', encoding='utf-8') as file:
        email_content = "".join(file.readlines())
    # Refer to https://stackoverflow.com/questions/49654499/python-extract-urls-from-email-messages
    regex_find_url = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
    urls = re.findall(regex_find_url, email_content)
    pattern_ip_numbers = r'http[s]?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'  
    res = {}

    for url in urls:
        if re.match(pattern_ip_numbers, url):
            res[url] = 0
        for s in ['bit.ly', 'tinyurl.com', 'cutt.ly']:
            if s in url:
                res[url] = 1                    
    return res

def analyze_subject(path_to_email):
    """Extract the subject of the email.

    Args:
        path_to_email (str): The file path to the .eml file.

    Returns:
        dict: A dictionary containing the email subject content.
    """
    with open(path_to_email, 'r', encoding='utf-8') as file:
        email_content = file.readlines()
    res = {}
    for line in email_content:
        if line.startswith('Subject'):
            res['Content'] = line[6].strip()
    return res

def analyze_attachment(path_to_email):
    """Extract attachments and calculate their SHA256 hashes.

    Args:
        path_to_email (str): The file path to the .eml file.

    Returns:
        dict: A dictionary where the key is the attachment filename and the value is its SHA256 hash.
    """
    with open(path_to_email, 'rb') as file:
        raw_message = email.message_from_binary_file(file)
    # Checking part of the file
    res = {}
    for part in raw_message.walk():
        if part.get_content_disposition() == 'attachment' or part.get_content_disposition() == 'inline':
            file_content = part.get_payload(decode=True)
            m = hashlib.sha256()
            m.update(file_content)
            if part.get_filename() != None:
                res[str(part.get_filename())] = m.hexdigest()
    return res

def analyze_extension(path_to_email):
    """Check the extension and content_type of attachments for potential threats.

    Args:
        path_to_email (str): The file path to the .eml file.

    Returns:
        dict: A dictionary containing attachment details and their assigned threat score 
              (0 is extremely dangerous, 1 is warning, 2 is normal).
    """
    with open(path_to_email, 'rb') as file:
        raw_message = email.message_from_binary_file(file)
    res = {}
    for part in raw_message.walk():       
        file_name = part.get_filename()
        content_type = part.get_content_type()
        # 0 is extremely dangerous, 1 is warning, 2 is normal
        if file_name != None and content_type != None:   
            extension = "".join(re.findall(r'(\..*$)',file_name.strip()))
            if extension in DANGEROUS_CONTENT_TYPES and content_type not in DANGEROUS_CONTENT_TYPES[extension]:
                res[file_name + ' ' + extension + ' ' + content_type] = 0
            elif extension in DANGEROUS_CONTENT_TYPES:
                res[file_name + ' ' + extension + ' ' + content_type] = 1
            else:
                res[file_name + ' ' + extension + ' ' + content_type] = 2
    return res