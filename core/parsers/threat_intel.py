import tldextract
import homoglyphs as hg

def analyze_homoglyph(header, urls):
    homoglyphs = hg.Homoglyphs(languages={'en'}, strategy=hg.STRATEGY_LOAD)

    homo_check = {}
    if 'email_domain_from' in header:
        clean_domain_from = header['email_domain_from'].strip()
        converted_domain_from = homoglyphs.to_ascii(clean_domain_from)
        if clean_domain_from not in converted_domain_from:
            homo_check['homoglyph_from'] = 1
        else:
            homo_check['homoglyph_from'] = 0
    else:
        homo_check['homoglyph_from'] = 0

    if 'email_domain_reply_to' in header:
        clean_domain_reply_to = header['email_domain_reply_to'].strip()
        converted_domain_reply_to = homoglyphs.to_ascii(clean_domain_reply_to)
        if clean_domain_reply_to not in converted_domain_reply_to:
            homo_check['homoglyph_reply_to'] = 1
        else:
            homo_check['homoglyph_reply_to'] = 0
    else:
        homo_check['homoglyph_reply_to'] = 0

    if 'email_domain_return_path' in header:
        clean_domain_return_path = header['email_domain_return_path'].strip()
        converted_domain_return_path = homoglyphs.to_ascii(clean_domain_return_path)
        if clean_domain_return_path not in converted_domain_return_path:
            homo_check['homoglyph_return_path'] = 1
        else:
            homo_check['homoglyph_return_path'] = 0
    else:
        homo_check['homoglyph_return_path'] = 0
    is_check_url = False

    list_domain = set()
                
    with open('./core/data/dataset/top-10000-domains.txt', 'r') as file:
        for line in file:
            line = line.strip().split('.')[0]
            list_domain.add(line)

    if urls:
        for url in urls:
            ext = tldextract.extract(url)
            clean_domain_url = ext.fqdn
            converted_domain_url = homoglyphs.to_ascii(clean_domain_url)
            for real_domain in list_domain:
                if (real_domain in converted_domain_url) and (clean_domain_url != real_domain):
                    homo_check['homoglyph_url'] = 1
                    is_check_url = True
                    break
    if not is_check_url:
        homo_check['homoglyph_url'] = 0

    return homo_check


def analyze_typo(header, urls):
    LEET_MAP = str.maketrans({'0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's', '7': 't', '@': 'a'})
    
    list_domain = set()
            
    with open('./core/data/dataset/top-10000-domains.txt', 'r') as file:
        for line in file:
            line = line.strip().split('.')[0]
            list_domain.add(line)

    typo_check = {}
    if 'email_domain_from' in header:
        domain = header['email_domain_from']
        domain = tldextract.extract(domain).domain.lower()
        raw_domain = domain.translate(LEET_MAP).lower()
        if raw_domain in list_domain:
            if raw_domain != domain:
                typo_check['email_domain_from'] = 1
        else:
            typo_check['email_domain_from'] = 0
    else:
        typo_check['email_domain_from'] = 0

    if 'email_domain_reply_to' in header:
        domain = header['email_domain_reply_to']
        domain = tldextract.extract(domain).domain.lower()
        raw_domain = domain.translate(LEET_MAP).lower()
        if raw_domain in list_domain:
            if raw_domain != domain:
                typo_check['email_domain_reply_to'] = 1
        else:
            typo_check['email_domain_reply_to'] = 0
    else:
        typo_check['email_domain_reply_to'] = 0

    if 'email_domain_return_path' in header:
        domain = header['email_domain_return_path']
        domain = tldextract.extract(domain).domain.lower()
        raw_domain = domain.translate(LEET_MAP).lower()
        if raw_domain in list_domain:
            if raw_domain != domain:
                typo_check['email_domain_return_path'] = 1
        else:
            typo_check['email_domain_return_path'] = 0
    else:
        typo_check['email_domain_return_path'] = 0

    is_check_url = False
    if urls:
        for domain in urls:
            domain = tldextract.extract(domain).domain.lower()
            raw_domain = domain.translate(LEET_MAP).lower()
            if raw_domain in list_domain:
                if 'email_domain_url' in header:
                    if raw_domain != domain:
                        typo_check['email_domain_url'] = 1
                        is_check_url = True
                        break
    if not is_check_url:
        typo_check['email_domain_url'] = 0

    return typo_check

            
