import re
from bs4 import BeautifulSoup
import ahocorasick
from core.email_analyzer.constants import PHISHING_EMAIL_KEYWORDS

def analyze_body_content(email_message):
    """Analyze the body contetn
    
    Args:
        email_file_path (str): The file path to the .eml file.

    Returns:
        dict: A dictionary containing the content of an email.
    """
    content_text = []
    content_html = []
    content_data = {}
    for part in email_message.walk():
        if part.get_content_type() == 'text/plain':
            raw_payload = part.get_payload(decode=True)
            charset = part.get_content_charset() or 'utf-8'
            content_text.append(raw_payload.decode(charset, errors='replace') + " ")
        if part.get_content_type() == 'text/html':
            raw_payload = part.get_payload(decode=True)
            charset = part.get_content_charset() or 'utf-8'
            soup = BeautifulSoup(raw_payload.decode(charset, errors='replace'), 'html.parser')
            for tag in soup(['script', 'style']):
                tag.decompose()
            res = soup.get_text(separator=" ")
            content_html.append(res.strip() + " ")
    content_text = ' '.join(content_text).split()
    content_html = ' '.join(content_html).split()
    if len(content_text) != 0:
        content_data['content'] = ' '.join(content_text[:3000])
    else:
        content_data['content'] = ' '.join(content_html[:3000])
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
    urgent_body['urgent_headers'] = list_of_urgent_body

    return urgent_body

def analyze_link_urls(body_text):
    """Extract and perform preliminary risk assessment of URLs found in the email.

    Args:
        email_file_path (str): The file path to the .eml file.

    Returns:
        dict: A dictionary where the key is the URL and the value is the suspicious score 
              (0 for raw IPs, 1 for shortened URLs).
    """
    regex_find_url = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
    urls = re.findall(regex_find_url, body_text)  
    
    regex_raw_ipv4 = r'https?://(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?(?:/[^\s]*)?'
    regex_raw_ipv6 = r'https?://\[?[0-9a-fA-F:]+\]?(?::\d+)?(?:/[^\s]*)?'
    
    url_risk_scores = {}
    SHORTENERS = {'bit.ly', 'tinyurl.com', 'cutt.ly'}
    
    
    unique_urls = set(urls)
    
    for url in unique_urls:

        if re.match(regex_raw_ipv4, url) or re.match(regex_raw_ipv6, url):
            url_risk_scores[url] = 0
            continue

        is_shortened = False
        for shortener in SHORTENERS:
            if shortener in url:
                url_risk_scores[url] = 1    
                is_shortened = True
                break   
                
        if not is_shortened:      
            url_risk_scores[url] = 2      
                   
    return url_risk_scores

def analyze_potential_passwords(raw_email_text):
    content = " ".join(raw_email_text.split())
    """Rule: 
                password | pass | pwd : 123
                password | pass | pwd is 123
                ...
    """        
    rule = r'\b(?:password|passwd|pwd|pass)(?:\s*(?:is|here|below))?\s*[:=\-]?\s*?(\S+)'
    pass_findings = re.findall(rule, content, re.IGNORECASE)
    pass_findings.extend(["", None])

    return pass_findings

