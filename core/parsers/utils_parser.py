import re
import tldextract

def extract_domain(line):
    """Extract the domain name from a string containing an email address.

    Args:
        line (str): The text line containing the email address.

    Returns:
        str: The extracted domain name.
    """
    extracted_info = tldextract.extract("".join(re.findall(r'@[^>]*', line)))
    return extracted_info.domain
