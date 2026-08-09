"""Configuration module containing blacklists and dangerous classes for AST analysis."""

black_list = {
    # System command execution (RCE)
    "os": {
        "system", "popen", "spawnl", "spawnv", "execl", "execv", 
        "posix_spawn", "posix_spawnp"
    },
    
    # Advanced process management, hidden shell command execution
    "subprocess": {
        "Popen", "run", "call", "check_output", "getoutput", "getstatusoutput"
    },
    
    # Dynamic Python code execution from strings (often combined with obfuscation)
    "builtins": {
        "eval", "exec", "compile", "__import__", "getattr"
    },
    
    # Insecure data deserialization triggering RCE
    "pickle": {
        "loads", "load", "Unpickler"
    },
    "marshal": {
        "loads", "load"
    },
    "shelve": {
        "open"
    },
    
    # Downloading malicious payloads from C2 (Command and Control) servers
    "urllib.request": {
        "urlopen", "urlretrieve"
    },
    "requests": {
        "get", "post", "request"
    },
    "http.client": {
        "HTTPConnection", "HTTPSConnection"
    },
    "socket": {
        "socket", "connect", "connect_ex"  # Used for Reverse Shell or Port Scanning
    },
    
    # Covert memory manipulation, security bypass, or code injection
    "ctypes": {
        "CDLL", "WinDLL", "memmove", "memset", "string_at"
    },
    "sys": {
        "settrace", "setprofile", "_getframe"  # Monitoring and manipulating code execution flow
    },
    
    # Decoding hidden data/shellcode (Obfuscated Data)
    "base64": {
        "b64decode", "b32decode", "a85decode", "b16decode"
    },
    "codecs": {
        "decode", "escape_decode"
    },
    "zlib": {
        "decompress"
    },
}

dangerous_classes = {
    "_wrap_close", 
    "Quitter", 
    "_IterationGuard",
    "CatchingIter"
}