import vt
from dotenv import load_dotenv
import os
from google import genai
from google.genai import types
load_dotenv()
import json

def check_hash(hash):
    api_virustotal_key = os.getenv("VIRUSTOTAL_API_KEY")
    with vt.Client(api_virustotal_key) as client:
        file = client.get_object(f"/files/{hash}")
    print(file.last_analysis_stats)
    return file.last_analysis_stats

def check_high_score(total_result):
    
    api_gemini_key = os.getenv('GEMINI_API_KEY')
    client = genai.Client(api_key=api_gemini_key)
    json_prompt = json.dumps(total_result, indent=4, ensure_ascii=False)
    with open('./Skills/AI_analyze.md', 'r', encoding='utf-8') as file:
        skill = file.read() 
    response = client.models.generate_content(
    model="gemini-3.1-flash-lite",
    contents=json_prompt,
    config=types.GenerateContentConfig(
        system_instruction=skill,
        temperature=0.1,
    ),
)


    print(response.text)

if __name__ == '__main__':
    check_hash('44d88612fea8a8f36de82e1278abb02f')
    check_high_score()