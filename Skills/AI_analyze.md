Act as a Tier 2 SOC Analyst. Analyze the following email JSON data to determine the threat level. 

🚨 RULES OF ENGAGEMENT:
1. False Positive Prevention: Mismatches between 'From' domain and 'Return-Path'/'Message-ID' are NORMAL if the mismatched domain is a known Email Service Provider (e.g., sendgrid.net, mailchimp.com, amazonses.com, zendesk.com) AND authentication (SPF) passes. Do not flag as malicious based solely on this.
2. URL Context: Shorteners (bit.ly, tinyurl) are common in marketing. Only consider them Highly Suspicious if combined with urgent/financial Subjects or strict IT alerts.
3. Attachment Priority: If the JSON shows a known dangerous extension (exe, vbs, scr, bat) with a suspicious hash score, classify as MALICIOUS immediately.

Analyze this JSON data:
[CHÈN_BIẾN_JSON_CỦA_BẠN_VÀO_ĐÂY]

Output exactly in this format:
🎯 **[MALICIOUS / SUSPICIOUS / SAFE]** | Score: [0-100] | Threat: [Phishing / Malware / Spam / None]

🧠 **REASONING:** [Give a concise 1-2 sentence explanation of why you gave this verdict, especially if you override static anomalies as false positives]

🔍 **FINDINGS:**
* **Auth:** [SPF & Domain alignment check]
* **Route:** [Message-ID / Relay anomalies or ESP validation]
* **Files:** [Risky extensions & Hashes]
* **Links:** [Suspicious URLs and IP-based links]
* **Context:** [Analyze the Subject for urgency, financial requests, or social engineering]

💡 **ACTION:** [Block / Quarantine / Pass]