import ast
import base64
from config import black_list, dangerous_classes
from environment import Environment


class Visitor(ast.NodeVisitor):
    """AST Node Visitor for analyzing and detecting dangerous Python code patterns.

    Attributes:
        alias_map_import (dict): Maps import aliases to their original module names.
        alias_map_importfrom (dict): Maps imported functions/classes to their origin modules.
        strings (list): Stores strings encountered during node visits.
        strings_assign (list): Stores strings specifically during assignment visits.
        env (Environment): The environment object tracking variable scopes and values.
        findings (list): A list of dictionaries containing the detected vulnerabilities.
    """

    def __init__(self):
        """Initializes the Visitor with empty states and a new Environment."""
        self.alias_map_import = dict()
        self.alias_map_importfrom = dict()
        self.strings = []          
        self.strings_assign = []
        self.env = Environment()
        self.findings = []
    
    def visit_FunctionDef(self, node):
        """Visits a FunctionDef node to track scopes inside functions.

        Args:
            node (ast.FunctionDef): The AST node representing a function definition.
        """
        # Creating a new dict when functiondef is called
        self.env.enter_scope()

        # Visit all the nodes inside the functiondef 
        self.generic_visit(node)

        # End the functiondef
        self.env.exit_scope()

    def visit_Call(self, node):
        """Visits a Call node to detect potentially dangerous function calls.

        Checks direct calls, aliased imports, and built-in functions against the blacklist.

        Args:
            node (ast.Call): The AST node representing a function call.
        """
        self.strings = []                                                

        # Check directly call function such as os.system and import
        if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
            
            if node.func.value.id in black_list:
                if node.func.attr in black_list[node.func.value.id]:
                    print(f'\t[-] Warning!!! There is {node.func.value.id}.{node.func.attr} in the file through call directly, at the line {node.lineno}')
                    
                    call_finding = {'type': '', 'function': '', 'args': '', 'kwargs': ''}
                    call_finding['type'] = 'Call'
                    call_finding['function'] = f'{node.func.value.id}.{node.func.attr}'
                    parsed_args = []
                    for arg in node.args:
                        evaluated_arg = self.evaluate_argument_value(arg)
                        if evaluated_arg:
                            parsed_args.append(str(evaluated_arg))

                    call_finding['args'] = ",".join(parsed_args)
                        
                            
                    for keyword in node.keywords:       
                        if isinstance(keyword, ast.keyword):
                            call_finding['kwargs'] = f'{keyword.arg}:{keyword.value.value}'
                    call_finding['line'] = node.lineno
                    self.findings.append(call_finding)

            elif self.alias_map_import.get(node.func.value.id) in black_list:
                if node.func.attr in black_list[self.alias_map_import.get(node.func.value.id)]:
                    print(f'\t[-] Warning!!! There is {node.func.value.id}.{node.func.attr} in the file through import alias, at the line {node.lineno}')
          
                    call_finding = {'type': '', 'function': '', 'args': '', 'kwargs': ''}
                    call_finding['type'] = 'Call'
                    call_finding['function'] = f'{node.func.value.id}.{node.func.attr}'
                    call_finding['solved_function'] = f'{self.alias_map_import[node.func.value.id]}.{node.func.attr}'
                    parsed_args = []
                    for arg in node.args:
                        
                        evaluated_arg = self.evaluate_argument_value(arg)
                        if evaluated_arg:
                            parsed_args.append(str(evaluated_arg))
                    call_finding['line'] = node.lineno
                    self.findings.append(call_finding)

        # Check import from and builtins call
        if isinstance(node.func, ast.Name):
            if node.func.id in self.alias_map_importfrom and self.alias_map_importfrom[node.func.id] in black_list:
                print(f'\t[-] Warning!!! There is {node.func.id} in the file through import from, at the line {node.lineno}')

                call_finding = {'type': '', 'function': '', 'args': '', 'kwargs': ''}
                call_finding['type'] = 'Call'
                call_finding['function'] = f'{node.func.id}'
                parsed_args = []
                for arg in node.args:
                    
                    evaluated_arg = self.evaluate_argument_value(arg)
                    if evaluated_arg:
                        parsed_args.append(str(evaluated_arg))
                call_finding['args'] = ",".join(parsed_args)
                call_finding['line'] = node.lineno
                self.findings.append(call_finding)

            elif node.func.id in black_list['builtins']:
                print(f'\t[-] Warning!!! There is {node.func.id} in the file through builtins, at the line {node.lineno}')
                
                call_finding = {'type': '', 'function': '', 'args': '', 'kwargs': ''}
                call_finding['type'] = 'Call'
                call_finding['function'] = f'{node.func.id}'
                parsed_args = []
                for arg in node.args:
                    
                    evaluated_arg = self.evaluate_argument_value(arg)
                    if evaluated_arg:
                        parsed_args.append(str(evaluated_arg))
                call_finding['args'] = ",".join(parsed_args)
                call_finding['line'] = node.lineno
                self.findings.append(call_finding)
                    # Implement backtracking method to find the value
                    

        # Check if a dangerous function is assigned to a variable
        try:
            for arg in node.args:
                self.visit(arg)
            if len(self.strings) == 1 and self.strings[0] in dangerous_classes:
                print(f"[-] Detected a dangerous function {self.strings[0]} assigned to a variable at the line {node.lineno}")
            elif len(self.strings) == 2:
                print(f"[-] Detected a dangerous function {'.'.join(self.strings)} assigned to a variable at the line {node.lineno}")
        except Exception as e:
            print(e)

        self.generic_visit(node)
    
    def visit_Import(self, node):
        """Visits an Import node to map aliases for blacklisted modules.

        Args:
            node (ast.Import): The AST node representing an import statement.
        """
        try:
            for alias in node.names:
                if alias.name in black_list:
                    if alias.asname not in self.alias_map_import:
                        self.alias_map_import[alias.asname] = alias.name
        except Exception as e:
            print(e)

        self.generic_visit(node)
    
    def visit_ImportFrom(self, node):
        """Visits an ImportFrom node to map imported items from blacklisted modules.

        Args:
            node (ast.ImportFrom): The AST node representing a 'from ... import ...' statement.
        """
        try:
            if node.module in black_list:
                for alias in node.names:
                    if alias.name in black_list[node.module]:
                        self.alias_map_importfrom[alias.name] = node.module
        except Exception as e:
            print(e)
        self.generic_visit(node)
    
    def evaluate_argument_value(self, node):
        """Recursively evaluates the value of an AST node argument.

        Supports resolving constants, binary operations, variable names (from env),
        and formatted strings (f-strings).

        Args:
            node (ast.AST): The AST node to evaluate.

        Returns:
            str: The string representation of the evaluated node, or an empty string if unresolved.
        """
        if isinstance(node, ast.Constant):
            return str(node.value)
        elif isinstance(node, ast.BinOp):
            left_node =  self.evaluate_argument_value(node.left)
            right_node = self.evaluate_argument_value(node.right)
            return str(left_node + right_node)
        elif isinstance(node, ast.Name) and self.env.get_variable(node.id) != None:
            return str(self.env.get_variable(node.id))
        elif isinstance(node, ast.JoinedStr):
            joined_string = ""
            for val in node.values:
                if isinstance(val, ast.Constant):
                    joined_string += str(val.value)
                elif isinstance(val, ast.FormattedValue):
                    evaluated_sub_value = self.evaluate_argument_value(val.value)
                    joined_string += evaluated_sub_value
            return str(joined_string)      

        return ""

    def visit_Assign(self, node):
        """Visits an Assign node to track variable values and dangerous assignments.

        Detects direct assignments of dangerous classes and handles decoding operations
        like base64 decoding for further analysis.

        Args:
            node (ast.Assign): The AST node representing an assignment statement.
        """
        self.strings_assign = []
        try:
            self.visit(node.value)
            if len(self.strings_assign) == 1:
                print(f"[-] Detected a dangerous function {self.strings_assign[0]} assigned to a variable at the line {node.lineno}")
            elif len(self.strings_assign) == 2:
                print(f"[-] Detected a dangerous function {'.'.join(self.strings_assign)} assigned to a variable at the line {node.lineno}")
        except Exception as e:
            print(e)
            
        for target in node.targets:
            extracted_arg_value = ''
            called_function_path = ''
            
            is_handled = False
            if isinstance(node.value, ast.Call):
                current_scope = self.env.get_current_scope()
                
                if len(node.value.args) > 0:
                    extracted_arg_value = self.evaluate_argument_value(node.value.args[0])
                if isinstance(node.value.func, ast.Attribute) and isinstance(node.value.func.value, ast.Name):                  
                    called_function_path = node.value.func.value.id + '.' + node.value.func.attr

            if 'base64' in called_function_path and isinstance(target, ast.Name) and isinstance(node.value, ast.Call):
                is_handled = True
                try:
                    self.env.set_variable(target.id, base64.b64decode(extracted_arg_value).decode('utf-8'))
                except Exception as e:
                    print(e)
            elif called_function_path.endswith('.decode') and isinstance(target, ast.Name) and isinstance(node.value, ast.Call):
                is_handled = True
                base_variable_name = node.value.func.value.id
                try:
                    self.env.set_variable(target.id, str(self.env.get_variable(base_variable_name)))
                except Exception as e:
                    print(e)
                    
            if not is_handled:
                evaluated_assignment_value = self.evaluate_argument_value(node.value)   
                if isinstance(target, ast.Name):
                    self.env.set_variable(target.id, str(evaluated_assignment_value))