"""Main execution module (Entry point) containing the CLI and orchestrating the analysis flow."""

import os
import sys
import argparse
import API
from analyzer import static_analyze

def user_input():   
    """Process the Command Line Interface (CLI) inputs to retrieve the list of files to analyze.

    Returns:
        list: A list containing paths to the .eml files to be analyzed.
    """
    parser = argparse.ArgumentParser(
                    prog='AnalyzeEmail',
                    description='This tool is used for analyzing email')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-f', '--file-name', help='Path to file .eml')
    group.add_argument('-fo', '--folder-name', help='Path to folder contains files .eml')
    args = parser.parse_args()
    list_email = []
    
    if args.file_name:
        if os.path.isfile(str(args.file_name)):
            list_email.append(args.file_name)
        else:
            print(f'The path to file is incorrect, please check again')
    elif args.folder_name:
        if os.path.isdir(str(args.folder_name)):
            for (root, dirs, files) in os.walk(args.folder_name):
                for file in files:
                    if file.endswith('.eml'):
                        list_email.append(os.path.join(root, file))
        else:
            print(f'The path to folder is incorrect, please check again')
            
    if len(list_email) == 0:
        print('Sorry, there is no .eml file to analyze')
        sys.exit(0)

    return list_email

def check_score(start_file, score):
    """Evaluate and classify the email based on the total risk score.

    Score interpretation:
    - 0 to 19: Safe (Normal).
    - 20 to 70: Abnormal (Requires further API AI check).
    - Greater than 70: Malicious (Malware).

    Args:
        start_file (static_analyze): The analysis object containing all extracted properties.
        score (int): The total score obtained from the evaluation process.

    Returns:
        dict: The result from the AI API (if the score falls within the abnormal range [20..70]).
    """
    if score < 19:
        print('This file is safe')
    elif score >= 19 and score <= 70:   
        total_result = {
            'header': start_file.header,
            'route' : start_file.route,
            'extension' : start_file.ext,
            'url' : start_file.url,
            'subject' : start_file.subject,
            'hash_of_file' : start_file.hash_of_file
        }        
        result_from_AI = API.check_high_score(total_result)
        return result_from_AI
    else:
        print('This file is malicious')

def main():
    """Main function to start the lifecycle of fetching and statically analyzing each file."""
    list_files = user_input()
    for file in list_files:
        print(f'---------- Analyzing the file {file} ----------')      
        start = static_analyze(file)
        start.runall()
        print(start.total_score)
        score = start.total_score
        check_score(start, score)
        print('\n'*5)
        
if __name__ == '__main__':
    main()