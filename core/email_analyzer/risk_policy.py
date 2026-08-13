THRESHOLDS = {
    'safe': 500,
    'suspicious': 65
}

AUTHENTICATION_SCORES = {
    'from_vs_return_path': 10,
    'from_vs_reply_to': 5,
    'from_vs_message_id': 5,
    'fail_dkim': 10,
    'not_pass_spf': 10
}


HEADER_SCORES = {
    'urgent_header': 10
}

URL_SCORES = {
    'raw_ip': 10,
    'shortened': 5
}

ATTACHMENT_SCORES = {
    'high_vt_warnings': 100,
    'ext_mismatch': 15,
    'dangerous_ext': 5,
    'macro_risk_high': 25,
    'macro_risk_medium': 15,
    'macro_risk_low': 0,
}

MACRO_LOGIC_SCORES = {
    'has_suspicious_flag': 3,
    'autoexec_1': 3,
    'autoexec_many': 6,
    'suspicious_kw_1': 4,
    'suspicious_kw_many': 6,
    'pattern_1': 4,
    'pattern_many': 6,
    'hex_max_score': 4,
    'has_iocs': 3,
    'has_base64': 2,
    'has_dridex': 4,
}

IDENTITY_SCORES = {
    'homoglyph_from': 20,
    'homoglyph_reply_to': 15,
    'homoglyph_return_path': 15,
    'homoglyph_url': 20,
    'typo_url': 20,
    'typo_from': 20,
    'typo_reply_to': 15,
    'typo_return_path': 15
}

BODY_SCORES = {
    'dangerous_content': 10
}
