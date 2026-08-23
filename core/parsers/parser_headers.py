import re
from .parser_utils import extract_domain
import ahocorasick
from core.email_analyzer.constants import PHISHING_EMAIL_KEYWORDS


def analyze_header(email_message):
    """Analyze the email Header to extract From, Return-Path, Reply-To, SPF, and DKIM information.

    Args:
        email_file_path (str): The file path to the .eml file.

    Returns:
        dict: A dictionary containing the extracted header information.
    """
        
    header_data = {}
    
    if email_message.get('From'):
        header_data['from'] = email_message.get('From')
        header_data['email_domain_from'] = extract_domain(header_data['from'])

    if email_message.get('Return-Path'):
        header_data['email_domain_return_path'] = extract_domain(email_message.get('Return-Path'))

    if email_message.get('Reply-To'):
        header_data['email_domain_reply_to'] = extract_domain(email_message.get('Reply-To'))

    if email_message.get('Message-ID'):
        header_data['message-id'] = email_message.get('Message-ID')

    if email_message.get('Delivered-To'):
        header_data['delivered-to'] = email_message.get('Delivered-To')

    if email_message.get('To'):
        header_data['to'] = email_message.get('To')

    for header_name, header_value in email_message.items():
        header_name_low = header_name.lower()

        if header_name_low == 'received-spf':
            if any(status in header_value for status in ['Fail', 'SoftFail', 'Neutral']):
                header_data['receive_spf'] = True
        if 'dkim_signature' in header_name_low or 'dkim-signature' in header_name_low:
            if 'Fail' in header_value:
                header_data['dkim_signature'] = True
    return header_data

def analyze_route(email_message):
    """Analyze the email routing and Message-ID.

    Args:
        email_file_path (str): The file path to the .eml file.

    Returns:
        dict: A dictionary containing the IPv4 address and Message-ID domain.
    """
    route_data = {}
    
    received_headers = email_message.get_all('Received', [])
    
    for received in received_headers:
        
        ip_match = re.search(r'\[(.*?)\]', received)
        if ip_match:
            # Get the first sender station
            route_data['ipv4'] = ip_match.group(1)
            break
            
    if email_message.get('Message-ID'):
        
        route_data['email_domain_message_id'] = extract_domain(email_message.get('Message-ID'))
            
    return route_data

def analyze_subject(email_message):
    """Extract the subject of the email.

    Args:
        email_message (email.message.Message): Đối tượng email đã được parse.

    Returns:
        dict: A dictionary containing the email subject content.
    """
    subject_data = {}

    if email_message.get('Subject'):
        subject_data['subject'] = email_message.get('Subject')
            
    return subject_data

def analyze_urgent_headers(raw_email_text):
    """Analyze the email content for urgent headers using the Aho-Corasick algorithm.

    Args:
        email_file_path (str): The file path to the .eml file.

    Returns:
            dict: A dictionary containing the email urgent headers.
    """
    
    automaton = ahocorasick.Automaton()
    urgent_headers = {}
    list_of_urgent_headers = []
    
    for idx, key in enumerate(PHISHING_EMAIL_KEYWORDS):
        automaton.add_word(key, (idx, key))
    automaton.make_automaton()
    
    for end_index, (insert_order, original_value) in automaton.iter(raw_email_text):
        start_index = end_index - len(original_value) + 1
        list_of_urgent_headers.append(original_value)
            
    urgent_headers['urgent_headers'] = list_of_urgent_headers

    return urgent_headers

