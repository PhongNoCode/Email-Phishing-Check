class Environment():
    """Manages the scope and variables for the AST analysis environment.

    Attributes:
        scopes (list): A stack of dictionaries representing variable scopes.
    """
    
    def __init__(self):
        """Initializes the Environment with a global scope."""
        self.scopes = [{}]

    def enter_scope(self):
        """Starts a new scope when entering a function definition."""
        self.scopes.append({})
    
    def exit_scope(self):
        """Ends the current scope when exiting a function definition.
        
        Returns:
            dict: The scope dictionary that was just removed, or None if only 
                  the global scope remains.
        """
        if len(self.scopes) > 1:
            return self.scopes.pop()

    def set_variable(self, var_name, value):
        """Adds or updates a variable's value in the current scope.
        
        Args:
            var_name (str): The name of the variable.
            value (Any): The value to assign to the variable.
        """
        current_scope = self.scopes[-1]
        current_scope[var_name] = value  

    def get_variable(self, var_name):
        """Retrieves a variable's value by searching from the innermost scope outwards.
        
        Args:
            var_name (str): The name of the variable to search for.
            
        Returns:
            Any: The value of the variable if found, otherwise None.
        """
        for scope in reversed(self.scopes):
            if var_name in scope:
                return scope[var_name]
        return None
    
    def get_current_scope(self):
        """Retrieves the current innermost scope.
        
        Returns:
            dict: The dictionary representing the current scope.
        """
        return self.scopes[-1]