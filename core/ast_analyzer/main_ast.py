import ast
import os
import json
import sys
from pathlib import Path

from ai import check_json_structure
from analyze_result_from_json import analyze_file

# Imported from separated files
from visitor import Visitor


def analyze_python_files():
    """Reads Python files from a directory and analyzes them for vulnerabilities.

    Walks through the specified directory, parses each Python file into an AST,
    uses the Visitor class to find dangerous function calls or assignments,
    and outputs the findings to a JSON report file.
    """
    # Read all Python files in the specified directory and its subdirectories
    python_file_paths = []
    for root, dirs, files in os.walk(r"D:\projects\DataScience\Email\Test"):
        for file_name in files:
            if file_name.endswith('.py'):
                python_file_paths.append(os.path.join(root, file_name))

    if len(python_file_paths) == 0:
        sys.exit(0)

    final_report = {"total_files": len(python_file_paths), "files": []}

    for file_path in python_file_paths:

        with open(file_path, "r", encoding="utf-8") as source_file:
            source_code = source_file.read()  

        # parser = ast.dump(ast.parse(source_code), indent = 4)
        print(f'[+] Analyzing code from file: {file_path}')
 
        ast_tree = ast.parse(source_code)
        
        ast_visitor = Visitor()

        ast_visitor.visit(ast_tree)

        file_analysis_report = {"file_path": file_path, 'findings': ast_visitor.findings}

        final_report["files"].append(file_analysis_report)
        
        print('\n')

    # Export findings to JSON
    with open(r'./Result/json_file_history.json', 'w', encoding='utf-8') as json_output_file:
        json.dump(final_report, json_output_file, indent=4)
            
        # print(ast_visitor.print_value())

    # with open(python_file_paths[2], "r", encoding="utf-8") as f:
    #         test_file = f.read()
            
    # print(ast.dump(ast.parse(test_file), indent = 4))


if __name__ == '__main__':
    print('\n')
    analyze_python_files()
    print('\n')
    # analyze_file()