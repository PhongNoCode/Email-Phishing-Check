import re
from .parser_utils import extract_domain
import ahocorasick
from core.email_analyzer.constants import PHISHING_EMAIL_KEYWORDS


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
    with open(email_file_path, 'r', encoding='utf-8') as file:
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

