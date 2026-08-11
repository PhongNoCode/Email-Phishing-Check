import re
import email
import hashlib
from oletools.olevba import VBA_Parser, detect_autoexec, detect_suspicious, detect_patterns
from core.email_analyzer.constants import DANGEROUS_CONTENT_TYPES


def analyze_attachment(email_file_path):
    """Extract attachments and calculate their SHA256 hashes.

    Args:
        email_file_path (str): The file path to the .eml file.

    Returns:
        dict: A dictionary where the key is the attachment filename and the value is its SHA256 hash.
    """
    with open(email_file_path, 'rb') as email_file:
        email_message = email.message_from_binary_file(email_file)
        
    attachment_hashes = {}
    for part in email_message.walk():
        if part.get_content_disposition() == 'attachment' or part.get_content_disposition() == 'inline':
            file_content = part.get_payload(decode=True)
            sha256_hasher = hashlib.sha256()
            sha256_hasher.update(file_content)
            
            if part.get_filename() != None:
                attachment_hashes[str(part.get_filename())] = sha256_hasher.hexdigest()
                
    return attachment_hashes


def analyze_extension(email_file_path):
    """Check the extension and content_type of attachments for potential threats.

    Args:
        email_file_path (str): The file path to the .eml file.

    Returns:
        dict: A dictionary containing attachment details and their assigned threat score 
              (0 is extremely dangerous, 1 is warning, 2 is normal).
    """
    with open(email_file_path, 'rb') as email_file:
        email_message = email.message_from_binary_file(email_file)
        
    extension_scores = {}
    for part in email_message.walk():       
        file_name = part.get_filename()
        content_type = part.get_content_type()
        
        # 0 is extremely dangerous, 1 is warning, 2 is normal
        if file_name != None and content_type != None:   
            extension = "".join(re.findall(r'(\..*$)', file_name.strip()))
            
            if extension in DANGEROUS_CONTENT_TYPES and content_type not in DANGEROUS_CONTENT_TYPES[extension]:
                extension_scores[file_name + ' ' + extension + ' ' + content_type] = 0
            elif extension in DANGEROUS_CONTENT_TYPES:
                extension_scores[file_name + ' ' + extension + ' ' + content_type] = 1
            else:
                extension_scores[file_name + ' ' + extension + ' ' + content_type] = 2
                
    return extension_scores


def analyze_email_macros(email_file_path):
    """Analyze the email for macros in attachments and extract relevant information."""
    with open(email_file_path, 'rb') as email_file:
            email_message = email.message_from_binary_file(email_file)
    macros = []
    for part in email_message.walk():
        try:
            if part.get_content_disposition() == 'attachment':
                with open(f'./core/outputs/{part.get_filename()}', 'wb') as attachment_file:
                    attachment_file.write(part.get_payload(decode=True))

                attachment_filename = str(part.get_filename())
                attachment_data = open('./core/outputs/'+attachment_filename, 'rb').read()
                vba_parser = VBA_Parser(attachment_filename, data=attachment_data)

                if vba_parser.detect_vba_macros():
                    vba_parser.analyze_macros()
                    for filename, stream_path, vba_filename, vba_code in vba_parser.extract_macros():
                        res_macro = {}
                        res_macro['attachment_name'] = attachment_filename
                        res_macro['vba_filename'] = vba_filename
                        if vba_parser.nb_autoexec > 0:
                            res_macro['autoexec'] = vba_parser.nb_autoexec
                        if vba_parser.nb_suspicious > 0:
                            res_macro['suspicious'] = vba_parser.nb_suspicious
                        if vba_parser.nb_iocs > 0:
                            res_macro['iocs'] = vba_parser.nb_iocs
                        if vba_parser.nb_hexstrings > 0:
                            res_macro['hexstrings'] = vba_parser.nb_hexstrings
                        if vba_parser.nb_base64strings > 0:
                            res_macro['base64strings'] = vba_parser.nb_base64strings
                        if vba_parser.nb_dridexstrings > 0:
                            res_macro['dridexstrings'] = vba_parser.nb_dridexstrings
                        if vba_parser.nb_vbastrings > 0:
                            res_macro['vbastrings'] = vba_parser.nb_vbastrings

                        auto_executable = []
                        autoexec_keywords = detect_autoexec(vba_code)
                        
                        if autoexec_keywords:
                            print('Auto-executable macro keywords found:')
                            for keyword, description in autoexec_keywords:
                                temp_res = '%s: %s' % (keyword, description)
                                auto_executable.append(temp_res)
                        suspicious_keywords = detect_suspicious(vba_code)
                        res_macro['autoexec_keywords'] = auto_executable

                        sus_keywords = []
                        if suspicious_keywords:
                            print('Suspicious VBA keywords found:')
                            for keyword, description in suspicious_keywords:
                                temp_res = '%s: %s' % (keyword, description)
                                sus_keywords.append(temp_res)
                        res_macro['suspicious_keywords'] = sus_keywords

                        patterns = detect_patterns(vba_code)
                        pattern = []
                        if patterns:
                            print('Patterns found:')
                            for pattern_type, value in patterns:
                                temp_res = '%s: %s' % (pattern_type, value)
                                pattern.append(temp_res)
                        res_macro['patterns'] = pattern     
                        macros.append(res_macro)
                    vba_parser.close() 
        except Exception as e:
            print(f"Error processing attachment {part.get_filename()}: {e}")                     
    return macros
