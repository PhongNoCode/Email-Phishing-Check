"""Module for handling external API integrations (VirusTotal and Google Gemini)."""

import os
import json
from dotenv import load_dotenv

import vt
from google import genai
from google.genai import types

load_dotenv()

# ==========================================
# 1. VIRUSTOTAL API
# ==========================================
def check_hash(file_hash):
    vt_api_key = os.getenv("VIRUSTOTAL_API_KEY")
    with vt.Client(vt_api_key) as client:
        vt_file_object = client.get_object(f"/files/{file_hash}")
    return vt_file_object.last_analysis_stats


# ==========================================
# 2. GEMINI API FOR EMAIL ANALYSIS
# ==========================================
def check_high_score(email_features):
    gemini_api_key = os.getenv('GEMINI_API_KEY')
    client = genai.Client(api_key=gemini_api_key)
    json_prompt = json.dumps(email_features, ensure_ascii=False, default=str)

    with open('./core/data/Skills/AI_analyze.md', 'r', encoding='utf-8') as prompt_file:
        system_prompt = prompt_file.read() 
        
    response = client.models.generate_content(
        model="gemini-3.1-flash-lite",
        contents=json_prompt,
        config=types.GenerateContentConfig(
            system_instruction=system_prompt,
            temperature=0.1,
        ),
    )
    return response.text

def check_bec(target_file):
    gemini_api_key = os.getenv('GEMINI_API_KEY')
    client = genai.Client(api_key=gemini_api_key)
    
    with open('./core/data/Skills/BEC.md', 'r', encoding='utf-8') as prompt_file:
        system_prompt = prompt_file.read() 
        
    with open('./core/outputs/output_to_AI.json', 'r') as data_file:
        content = data_file.readlines()
        
    response = client.models.generate_content(
        model="gemini-3.1-flash-lite",
        contents=content,
        config=types.GenerateContentConfig(
            system_instruction=system_prompt,
            temperature=0.1,
        ),
    )   
    return response.text


# ==========================================
# 3. GEMINI API FOR AST PYTHON ANALYSIS
# ==========================================
def analyze_json_structure():
    """Reads the JSON history and uses Gemini AI to analyze the AST structure."""
    gemini_api_key = os.getenv('GEMINI_API_KEY')
    client = genai.Client(api_key=gemini_api_key)
    
    with open('./core/outputs/json_file_history.txt', 'r', encoding='utf-8') as history_file:
        json_commands = history_file.readlines()
        
    with open('./core/data/Skills/Skills.md', 'r', encoding='utf-8') as skills_file:
        system_prompt = skills_file.readlines()
        
    response = client.models.generate_content(
        model="gemini-3.1-flash-lite",
        contents=f"Analyze this file:\n{json_commands}",
        config=types.GenerateContentConfig(
            system_instruction=system_prompt,
            temperature=0.2,
        ),
    )
    return response.text


