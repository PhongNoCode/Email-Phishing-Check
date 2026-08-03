# 🛡️ Email Phishing Analyzer

**Email Phishing Analyzer** is a robust, modular Python command-line tool designed for static analysis of `.eml` files. It evaluates email headers, routing information, URLs, and attachments to detect phishing attempts, spoofing, and malicious payloads.

## ✨ Features

- **Header & Spoofing Analysis:** Cross-checks `From`, `Return-Path`, `Reply-To`, and `Message-ID` domains to detect impersonation.
- **Authentication Checks:** Evaluates SPF and DKIM signatures for email integrity.
- **Attachment Threat Detection:** 
  - Extracts attachments and calculates their SHA256 hashes.
  - Validates file extensions and content types against a known dangerous list.
  - Integrates with **VirusTotal API** for malicious hash lookups.
  - Intergrates with **Gemini AI model** for analyze suspicious email.
- **URL Extraction:** Identifies suspicious links, raw IP URLs, and shortened URLs (e.g., bit.ly).
- **High Performance:** Utilizes `concurrent.futures.ThreadPoolExecutor` for concurrent scanning and analysis, significantly reducing processing time.
- **Smart Scoring System:** Categorizes emails into `Safe`, `Abnormal`, and `Malicious` based on an aggregated risk score.

## 📁 Project Structure

```
Email-Phishing-Check/
├── constants.py      # Static configurations and dangerous content types
├── parsers.py        # Functions for extracting data from .eml files
├── analyzer.py       # Core static analysis, scoring logic, and threading
├── main.py           # CLI entry point and execution flow
├── API.py            # External API integrations (VirusTotal and Gemini)
├── .gitignore        # Ignored files and folders
├── .env.example      # Example API inputs
├── email-test        # Sample emails
├── requirements.txt  # Libraries for this project
└── README.md         # Project documentation
```

## 💻 Clone the repository:

```
git clone https://github.com/PhongNoCode/Email-Phishing-Check.git
cd Email-Phishing-Check
pip install -r requirements.txt
```

### ⚙️ Configuration (Environment Variables)

This project requires API keys to function correctly. We use a `.env` file to securely manage these credentials.

1. Locate the `.env.example` file in the root directory.
2. Duplicate this file and rename the copy to `.env` (do not delete the dot at the beginning).
   - **Linux/macOS:** `cp .env.example .env`
   - **Windows:** `copy .env.example .env`
3. Open the newly created `.env` file in your text editor and replace the placeholder values with your actual API keys:

```
VIRUSTOTAL_API_KEY=your_real_virustotal_api_key
GEMINI_API_KEY=your_real_ai_api_key
```
## 📄 Usage for single mail:

```
python main.py -f path/to/email.eml
```

## 🗂️ Usage for multiple mails in a folder:

```
python main.py -fo path/to/folder/
```

## 🔎 Sample output

<img width="2410" height="1120" alt="image" src="https://github.com/user-attachments/assets/f255b820-a95c-4dcd-8eaf-0e7f1994d695" />


