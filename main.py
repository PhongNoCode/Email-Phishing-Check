"""Main execution module (Entry point) containing the CLI and orchestrating the analysis flow."""

import os
import sys
import argparse
from rich.console import Console

from core.utils import api
from core.email_analyzer import bec_analyzer
from core.email_analyzer.analyzer import StaticAnalyzer
from core.email_analyzer.parse_text_to_json import parse_text
from core.email_analyzer.risk_policy import THRESHOLDS

console = Console()

def get_target_files():   
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
    
    email_file_paths = []
    
    if args.file_name:
        if os.path.isfile(str(args.file_name)):
            email_file_paths.append(args.file_name)
        else:
            print('The path to file is incorrect, please check again')
    elif args.folder_name:
        if os.path.isdir(str(args.folder_name)):
            for (root, dirs, files) in os.walk(args.folder_name):
                for file in files:
                    if file.endswith('.eml'):
                        email_file_paths.append(os.path.join(root, file))
        else:
            print('The path to folder is incorrect, please check again')
            
    if len(email_file_paths) == 0:
        print('Sorry, there is no .eml file to analyze')
        sys.exit(0)

    return email_file_paths

def evaluate_risk_score(analyzer_instance, risk_score):
    """Evaluate and classify the email based on the total risk score.

    Args:
        analyzer_instance (StaticAnalyzer): The analysis object containing all extracted properties.
        risk_score (int): The total score obtained from the evaluation process.

    Returns:
        dict: The result from the AI API.
    """
    if risk_score < THRESHOLDS['safe']:
        console.print("\n[bold green]===============================================[/bold green]")
        console.print(f"[bold green] ESTIMATED RISK SCORE : [bold black on green] {risk_score} [/bold black on green][/bold green]")
        console.print("[bold green]===============================================[/bold green]\n")
        console.print('[bold green]This file is safe[/bold green]')
        
    elif risk_score < THRESHOLDS['suspicious']:   
        email_features = {
            'header': analyzer_instance.header,
            'route' : analyzer_instance.route,
            'extension' : analyzer_instance.ext,
            'url' : analyzer_instance.url,
            'subject' : analyzer_instance.subject,
            #'hash_of_file' : analyzer_instance.hash_of_file,
            'urgent_headers' : analyzer_instance.urgent_headers,
            'macro_analysis' : analyzer_instance.macro_analysis,
            'homoglyph': analyzer_instance.homoglyph,
            'typo': analyzer_instance.typo
        }
        console.print("\n[bold orange1]===============================================[/bold orange1]")
        console.print(f"[bold orange1] ESTIMATED RISK SCORE : [bold black on orange1] {risk_score} [/bold black on orange1][/bold orange1]")
        console.print("[bold orange1]===============================================[/bold orange1]\n")
        
        ai_evaluation_result = api.check_high_score(email_features)
        return ai_evaluation_result
        
    else:        
        console.print("\n[bold red]===============================================[/bold red]")
        console.print(f"[bold red] ESTIMATED RISK SCORE : [bold black on red] {risk_score} [/bold black on red][/bold red]")
        console.print("[bold red]===============================================[/bold red]\n")
        console.print('[bold red]This file is malicious[/bold red]')

def generate_bec_report(file_path):
    bec_report_content = api.check_bec(file_path)
    with open('./core/outputs/report.html', 'w', encoding='utf-8') as result_file:
        result_file.write(bec_report_content)

def main():
    """Main function to start the lifecycle of fetching and statically analyzing each file."""
    target_files = get_target_files()
    for file_path in target_files:
        print()
        print(f'---------- Analyzing the file {file_path} ----------')      
        analyzer = StaticAnalyzer(file_path)
        analyzer.run_all()
        risk_score = analyzer.total_score
        
        print(evaluate_risk_score(analyzer, risk_score))
        print('\n' * 5)

    parse_text()
    generate_bec_report('./core/outputs/output_to_AI.json')
    console.print('[yellow]Analyzed BEC Successfully!!!![/yellow] You can check the output by clicking in the [blue]./core/outputs/report.html[/blue]')
        
if __name__ == '__main__':
    main()
