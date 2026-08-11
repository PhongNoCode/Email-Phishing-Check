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
    if urls:
        for url in urls:
            ext = tldextract.extract(url)
            clean_domain_url = ext.fqdn
            converted_domain_url = homoglyphs.to_ascii(clean_domain_url)
            if clean_domain_url not in converted_domain_url:
                homo_check['homoglyph_url'] = 1
                is_check_url = True
                break
    if not is_check_url:
        homo_check['homoglyph_url'] = 0

    return homo_check
