import ast

class XSSAnalyzer(ast.NodeVisitor):
    def __init__(self):
        self.vulnerable_functions = []
        self.current_function = None

    def visit_FunctionDef(self, node):
        self.current_function = node.name
        self.generic_visit(node)

    def visit_Call(self, node):
        # Check for potentially dangerous methods or functions that could lead to XSS.
        if self.is_dangerous_method(node):
            self.vulnerable_functions.append(self.current_function)
        self.generic_visit(node)

    def is_dangerous_method(self, node):
        """
        Identifies calls to methods or functions that could potentially lead to XSS if not properly sanitized.
        """
        dangerous_methods = {'render_to_response', 'HttpResponse', 'mark_safe'}
        dangerous_functions = {'exec', 'eval', 'getattr', 'setattr'}

        # Check method calls within HTML rendering contexts or exec/eval uses
        if isinstance(node.func, ast.Attribute) and node.func.attr in dangerous_methods:
            return True
        if isinstance(node.func, ast.Name) and node.func.id in dangerous_functions:
            return True

        # Check for dynamic attribute access that could be exploited for XSS
        if isinstance(node.func, ast.Call) and node.func.func.id == 'getattr':
            return True

        return False

def analyze_file_for_xss(file_path):
    with open(file_path, "r") as source:
        tree = ast.parse(source.read())
    analyzer = XSSAnalyzer()
    analyzer.visit(tree)
    return analyzer.vulnerable_functions

def check_xss(input_string):
    """
    Check if the input string is vulnerable to XSS (Cross-Site Scripting).

    Parameters:
        input_string (str): The input string to analyze.

    Returns:
        bool: True if the input is vulnerable to XSS, False otherwise.
    """
    # Example: Detect common XSS patterns
    xss_patterns = [
        "<script>", "</script>", "javascript:", "onerror=", "onload=", "alert(", "<img", "<iframe"
    ]
    return any(pattern.lower() in input_string.lower() for pattern in xss_patterns)




# Example usage
def main():
    file_path = 'example_code.py'
    vulnerabilities = analyze_file_for_xss(file_path)
    if vulnerabilities:
        print(f"Potential XSS vulnerabilities found in the following functions in {file_path}:")
        for func in vulnerabilities:
            print(f" - Function: {func}")
    else:
        print("No potential XSS vulnerabilities found.")

if __name__ == "__main__":
    main()
