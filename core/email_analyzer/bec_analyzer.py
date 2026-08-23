"""Module for extracting and analyzing Business Email Compromise (BEC) indicators."""

import os

sender_receiver_map: dict[str, list] = {}
is_file_cleared = False

def analyze_bec(header, subject, body_content):
    
    combined_email_data = dict(header)
    combined_email_data.update(subject)
    combined_email_data.update(body_content)
    
    markdown_content = ''
    
    if ('delivered-to' in header or 'to' in header) and 'from' in header:
        if 'delivered-to' in header:
            communication_key = header['delivered-to'] + '::' + header['from']
        else:
            communication_key = header['to'] + '::' + header['from']
        
        if communication_key not in sender_receiver_map:
            sender_receiver_map[communication_key] = []
            
        extracted_fields_list = []
        for key, value in combined_email_data.items():
            if key not in ['delivered-to', 'from']:
                extracted_fields_list.append(f'{key}:{value}')

        markdown_content += f'Key Title: {communication_key}\n'
        for part in extracted_fields_list:
            markdown_content += f'{part}\n'
        markdown_content += '-----------------------\n'
        
        # Clear old content before analyzing
        if os.path.isfile('./core/outputs/Raw_BEC.txt'):
            global is_file_cleared
            if is_file_cleared == False:
                is_file_cleared = True
                clear_old_file = open("./core/outputs/Raw_BEC.txt", "w").close()
        
        with open('./core/outputs/Raw_BEC.txt', 'a+', encoding='utf-8') as output_file:
            write_result = output_file.writelines(markdown_content)