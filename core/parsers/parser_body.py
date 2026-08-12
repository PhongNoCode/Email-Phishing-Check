import re
import email

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


