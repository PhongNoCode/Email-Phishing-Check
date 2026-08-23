import ast
import os
import json
from core.ast_analyzer.visitor import Visitor
import os
import json
import ast
from core.ast_analyzer.visitor import Visitor 

def analyze_python_files(extracted_files):
    """Reads Python files from extracted attachments and analyzes them for vulnerabilities.

    Collects all .py files, parses each into an AST,
    uses the Visitor class to find dangerous function calls or assignments,
    and outputs the findings to a JSON report file.
    """

    python_file_paths = []
    for original_file_name, file_paths in extracted_files.items():
        for file_path in file_paths:
            if file_path.lower().endswith('.py'):
                python_file_paths.append(file_path)

    if len(python_file_paths) == 0:
        return None

    final_report = {"total_files": len(python_file_paths), "files": []}

    for file_path in python_file_paths:
        try:
            with open(file_path, "r", encoding="utf-8") as source_file:
                source_code = source_file.read()  

            print(f'[+] Analyzing code from file: {file_path}')

            ast_tree = ast.parse(source_code)
            
            ast_visitor = Visitor()
            ast_visitor.visit(ast_tree)

            file_analysis_report = {"file_path": file_path, 'findings': ast_visitor.findings}
            final_report["files"].append(file_analysis_report)
            
            print('\n')
            
        except Exception as e:
            print(f'[-] Error analyzing {file_path}: {e}\n')
            
            final_report["files"].append({"file_path": file_path, "error": str(e)})

    output_dir = r"./core/outputs"
    
    os.makedirs(output_dir, exist_ok=True) 
    
    output_file_path = os.path.join(output_dir, "ast_report.json")

    existing_json_format = []
    
    if os.path.isfile(output_file_path):
        try:
            with open(output_file_path, 'r', encoding='utf-8') as f:
                content = f.read().strip()
                if content:
                    existing_json_format = json.loads(content)
                    if not isinstance(existing_json_format, list):
                        existing_json_format = [existing_json_format]
        except json.JSONDecodeError:
            pass
    existing_json_format.append(final_report)

    
    with open(output_file_path, 'w', encoding='utf-8') as json_output_file:
        json.dump(existing_json_format, json_output_file, indent=4)
        
    
    return final_report
            
