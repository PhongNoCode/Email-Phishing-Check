import re
import email
from bs4 import BeautifulSoup
import ahocorasick
from core.email_analyzer.constants import PHISHING_EMAIL_KEYWORDS

def analyze_body_content(email_file_path):
    """Analyze the body contetn
    
    Args:
        email_file_path (str): The file path to the .eml file.

    Returns:
        dict: A dictionary containing the content of an email.
    """
    with open(email_file_path, 'rb') as email_file:
        email_message = email.message_from_binary_file(email_file)
    content_text = ''
    content_html = ''
    content_data = {}
    for part in email_message.walk():
        if part.get_content_type() == 'text/plain':
            raw_payload = part.get_payload(decode=True)
            charset = part.get_content_charset() or 'utf-8'
            content_text += raw_payload.decode(charset, errors='replace') + " "
        if part.get_content_type() == 'text/html':
            raw_payload = part.get_payload(decode=True)
            charset = part.get_content_charset() or 'utf-8'
            soup = BeautifulSoup(raw_payload.decode(charset, errors='replace'), 'html.parser')
            for tag in soup(['script', 'style']):
                tag.decompose()
            res = soup.get_text(separator=" ")
            content_html += res.strip() + " "
    content_text = ' '.join(content_text.split())
    content_html = ' '.join(content_html.split())
    if len(content_text) != 0:
        content_data['content'] = content_text[:3000] if len(content_text) >= 3000 else content_text
    else:
        content_data['content'] = content_html[:3000] if len(content_html) >= 3000 else content_html
    return content_data

def analyze_urgent_body_content(body_content):
    automaton = ahocorasick.Automaton()
    urgent_body = {}
    list_of_urgent_body = []

    
    haystack = body_content.get('content')
    for idx, key in enumerate(PHISHING_EMAIL_KEYWORDS):
        automaton.add_word(key, (idx, key))
    automaton.make_automaton()
    for end_index, (insert_order, original_value) in automaton.iter(haystack):
        start_index = end_index - len(original_value) + 1
        list_of_urgent_body.append(original_value)
        assert haystack[start_index:start_index + len(original_value)] == original_value
    urgent_body['urgent_headers'] = list_of_urgent_body

    return urgent_body

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
            continue
            
        for shortener in ['bit.ly', 'tinyurl.com', 'cutt.ly']:
            if shortener in url:
                url_risk_scores[url] = 1    
                continue         
        url_risk_scores[url] = 2      
                
    return url_risk_scores


