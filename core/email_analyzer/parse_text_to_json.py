"""Parses email data from 'Raw_BEC.txt' and exports it to a JSON file.

This script reads a raw text file containing email information, extracts 
relevant fields, and organizes them into a dictionary structure. It identifies
data blocks starting with 'Key Title' and uses regular expressions to extract
headers such as 'message-id', 'email_domain_from', 'email_domain_reply_to', 
'to', and 'subject'. The extracted values are stored in sets to prevent duplicates.
The email body content is concatenated until a separator line 
('-----------------------') is encountered, which triggers the aggregation of 
the temporary data into the main dictionary and resets the temporary variables. 
Finally, the processed data is serialized and written to 'output_to_AI.json', 
with sets automatically converted to lists.
"""

import json
import re

def parse_text():
    parsed_email_data: dict[str, dict] = {}
    current_title_key = ''
    body_content = ''
    current_extracted_fields: dict[str, set] = {}
    
    with open('./core/outputs/Raw_BEC.txt', 'r') as input_file:
        for line in input_file.readlines():
            field_key = "".join(re.findall(r'(.*[a-z]):', line)).strip()
            field_value = "".join(re.findall(r'\:(.*)', line)).strip()
            
            if line.startswith('Key Title'):
                if line not in parsed_email_data:
                    parsed_email_data[line] = {}
                    current_title_key = line
                else:
                    current_title_key = line
                    
            elif line.startswith(('message-id', 'email_domain_from', 'email_domain_reply_to', 'to', 'subject')):
                if field_key not in current_extracted_fields:
                    current_extracted_fields[field_key] = set()
                current_extracted_fields[field_key].add(field_value)
                
            elif line.startswith('-----------------------'):
                current_extracted_fields['content'] = set()
                current_extracted_fields['content'].add(body_content[8:])
                
                for keyword in current_extracted_fields:
                    if keyword not in parsed_email_data[current_title_key]:
                        parsed_email_data[current_title_key][keyword] = set()
                    parsed_email_data[current_title_key][keyword].update(current_extracted_fields[keyword])
                    
                current_title_key = ''
                body_content = ''
                current_extracted_fields = {}
                
            else:
                body_content += line.strip()

    with open('./core/outputs/output_to_AI.json', 'w', encoding='utf-8') as output_file:
        output_file.write(json.dumps(parsed_email_data, default=list, separators=(',', ':')))