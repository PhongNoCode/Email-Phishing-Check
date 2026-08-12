"""Module for extracting and analyzing Business Email Compromise (BEC) indicators."""

from core.parsers import analyze_header, analyze_subject, analyze_content
import os

sender_receiver_map: dict[str, list] = {}
is_file_cleared = False

def analyze_bec(email_file_path):
    header_data = analyze_header(email_file_path)
    subject_data = analyze_subject(email_file_path)
    content_data = analyze_content(email_file_path)  
    
    combined_email_data = dict(header_data)
    combined_email_data.update(subject_data)
    combined_email_data.update(content_data)
    
    markdown_content = ''
    
    if 'delivered-to' in header_data and 'from' in header_data:
        communication_key = header_data['delivered-to'] + '::' + header_data['from']
        
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