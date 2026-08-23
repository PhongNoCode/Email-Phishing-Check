import hashlib
from oletools.olevba import VBA_Parser, detect_autoexec, detect_suspicious, detect_patterns
from core.email_analyzer.constants import DANGEROUS_CONTENT_TYPES, OFFICE_EXTENSIONS        
import pymupdf
import zipfile
import io
import os
import magic


def analyze_attachment(extracted_files):
    """Extract attachments and calculate their SHA256 hashes.

    Args:
        email_file_path (str): The file path to the .eml file.

    Returns:
        dict: A dictionary where the key is the attachment filename and the value is its SHA256 hash.
    """
        
    attachment_hashes = {}
    for original_file_name, file_paths in extracted_files.items():
        for file_path in file_paths:
            with open(file_path, 'rb') as f:
                file_hash = hashlib.file_digest(f, 'sha256').hexdigest()
            attachment_hashes[os.path.basename(file_path)] = file_hash
    return attachment_hashes


def analyze_extension(extracted_files):
    """Check the extension and content_type of attachments for potential threats.

    Args:
        email_file_path (str): The file path to the .eml file.

    Returns:
        dict: A dictionary containing attachment details and their assigned threat score 
              (0 is extremely dangerous, 1 is warning, 2 is normal).
    """       
    extension_scores = {}
    for original_file_name, file_paths in extracted_files.items():
        for file_path in file_paths:      
            file_name = os.path.basename(file_path)
            content_type = magic.from_file(file_path, mime=True)
            if content_type is None:
                content_type = "application/octet-stream"
            
            # 0 is extremely dangerous, 1 is warning, 2 is normal
            extension = os.path.splitext(file_name)[1].lower()
                
            if extension in DANGEROUS_CONTENT_TYPES and content_type not in DANGEROUS_CONTENT_TYPES[extension]:
                extension_scores[file_name + ' ' + extension + ' ' + content_type] = 0
            elif extension in DANGEROUS_CONTENT_TYPES:
                extension_scores[file_name + ' ' + extension + ' ' + content_type] = 1
            else:
                extension_scores[file_name + ' ' + extension + ' ' + content_type] = 2
                
    return extension_scores

def analyze_email_macros(extracted_files):
    """Analyze the email for macros in attachments and extract relevant information.
    
        Args:
            email_message (obj): all email.
    
        Returns:
            dict: A dictionary containing attachment details and their assigned threat score.
        """      
    macros = []
    for original_file_name, file_paths in extracted_files.items():
        for file_path in file_paths:
            if not file_path.lower().endswith(OFFICE_EXTENSIONS):
                continue
            try:
                vba_parser = VBA_Parser(file_path)

                if vba_parser.detect_vba_macros():
                    vba_parser.analyze_macros()
                    for vba_filename, vba_code in vba_parser.extract_macros():
                        res_macro = {}
                        res_macro['attachment_name'] = os.path.basename(file_path)
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
                print(f"Error processing attachment {os.path.basename(file_path)}: {e}")                      
    return macros

#   https://www.kaggle.com/datasets/beatoa/spamassassin-public-corpus/data
def analyze_pdf(extracted_files):
    for original_file_name, file_paths in extracted_files.items():
        for file_path in file_paths:
            if file_path.lower().endswith('.pdf'):
                try:
                    doc = pymupdf.open(file_path)
                    for i, page in enumerate(doc):
                        pix = page.get_pixmap(dpi=200)
                        safe_base_name = os.path.basename(file_path)
                        img_path = f"./core/outputs/{safe_base_name}_page-{i+1}.png"
                        pix.save(img_path)
                        print(page.get_text())
                except Exception as e:
                    print(e)
    return 


def analyze_universal_extract(email_message, password):
    extracted_files = {}
    for part in email_message.walk():
        if part.get_content_disposition() not in ['attachment', 'inline']:
            continue
        
        file_name = part.get_filename()
        file_content = part.get_payload(decode=True)    

        if not file_name or not file_content:
            continue
        
        if file_name.lower().endswith('.zip'):
            with zipfile.ZipFile(io.BytesIO(file_content)) as archive:
                if len(archive.namelist()) == 0:
                    continue
                for passwd in password:
                    try:
                        is_file = False
                        pwd = passwd.encode('utf-8') if passwd else None
                        for name in archive.namelist():
                            if not name.endswith('/'):
                                is_file = True
                                archive.read(name, pwd=pwd)
                                break
                        if is_file:
                            extracted_files[file_name] = []
                            for name in archive.namelist():
                                extracted_files[file_name].append(f'./core/data/output/files/{file_name[:-4]}/{name}')
                            archive.extractall(f'./core/data/output/files/{file_name[:-4]}/', pwd=pwd)
                            print(f'The correct password is: {passwd if passwd else "No password"}')
                            break
                    except Exception as e:
                        pass
        else:
            try:
                output_dir = './core/outputs/files/'
                os.makedirs(output_dir, exist_ok=True)
                
                safe_file_name = os.path.basename(file_name)
                file_path = os.path.join(output_dir, safe_file_name)
                
                with open(file_path, 'wb') as f:
                    f.write(file_content)
                
                extracted_files[file_name] = [file_path]
            except Exception as e:
                print(f"Error saving direct attachment {file_name}: {e}")
    return extracted_files
            
