"""Module containing constants and static configurations for the email analysis system."""

DANGEROUS_CONTENT_TYPES = {
    '.exe': [
        'application/x-msdownload',
        'application/x-msdos-program',
        'application/exe',
        'application/x-exe',
        'application/octet-stream',
    ],
    '.bat': [
        'application/bat',
        'application/x-bat',
        'text/x-bat',
    ],
    '.vbs': [
        'application/x-vbs',
        'text/vbscript',
        'application/vnd.ms-vbscript',
    ],
    '.js': [
        'application/javascript',
        'application/x-javascript',
        'text/javascript',
    ],
    '.scr': [
        'application/x-screensaver',
        'application/octet-stream',
    ],
    '.iso': [
        'application/x-iso9660-image',
    ],
    '.cab': [
        'application/vnd.ms-cab-compressed',
    ],
}



PHISHING_EMAIL_KEYWORDS = [
    # Urgency
    "urgent", "immediate action required", "act now", "expires today",
    "expires soon", "account suspended", "account locked",
    "account will be closed", "verify your account immediately",
    "final notice", "last warning", "your account has been limited",
    "within 24 hours", "within 48 hours", "within 12 hours",
    "before it expires", "before your account is closed",
    "avoid suspension", "avoid termination", "to avoid interruption",
    "to prevent account closure", "immediate verification required",
    "urgent verification required",

    # Sensitive info requests
    "verify your account", "verify your identity", "verify your password",
    "confirm your details", "confirm your information",
    "update your billing information", "update your payment information",
    "click here to verify", "provide your social security number",
    "enter your credit card details", "confirm your password",

    # Authentication / Login
    "authentication required", "authentication failed",
    "reauthenticate", "re-authenticate",
    "session expired", "session has expired",
    "sign-in attempt", "login attempt",
    "new login detected", "new device detected",
    "verify login", "verify sign-in",
    "confirm login", "confirm sign-in",
    "unlock your account", "restore access",
    "restore your account", "secure your account",

    # MFA / Verification Codes
    "verification code", "security code",
    "one-time code", "one time password",
    "otp", "mfa verification",
    "two-factor authentication", "two factor authentication",
    "authentication code", "enter the code",
    "enter verification code", "approve sign-in",

    # Credential / Password
    "password reset required", "password reset request",
    "password has expired", "password expires",
    "change your password", "confirm your login credentials",
    "verify your credentials", "account credentials",
    "credentials have expired", "credentials compromised",

    # Financial / transaction
    "unauthorized transaction", "unauthorized activity detected",
    "refund", "invoice attached", "payment failed",
    "you have won", "congratulations you've been selected",
    "claim your prize", "claim your reward", "tax refund",
    "bank transfer", "wire transfer required",
    "payment authorization required", "payment verification required",
    "payment method declined", "payment method expired",
    "card verification required", "billing information required",
    "billing details", "transaction verification",
    "bank account verification", "beneficiary verification",
    "recipient verification",

    # Call-to-action links
    "click here", "click below", "login here", "sign in now",
    "download attachment", "reset your password", "update now",
    "verify now", "confirm now",
    "follow this link", "follow the link below",
    "use the link below", "access the secure portal",
    "secure link", "secure portal",
    "login portal", "account portal",
    "click the button below", "open the link",

    # Impersonation phrasing
    "dear valued customer", "dear user", "dear customer",
    "security alert", "security notice", "it department",
    "helpdesk notification", "system administrator",
    "message from your administrator", "your administrator",
    "IT support", "IT support team", "technical support",
    "security team", "account security team",
    "Microsoft support", "Google support", "Apple support",
    "Amazon support",

    # Threats / consequences
    "failure to comply", "legal action will be taken",
    "your access will be terminated", "suspicious activity detected",
    "unusual sign-in activity", "your account has been compromised",

    # Delivery / Postal Scams
    "delivery attempt failed", "package pending", "unpaid shipping fee",
    "track your shipment", "customs clearance required",
    "reschedule delivery", "undelivered package",
    "shipping address error", "parcel detained",

    # Workplace / Corporate / HR
    "mandatory compliance training", "salary adjustment",
    "employee benefits update", "review attached document",
    "docusign document waiting", "w-2 form",
    "payroll update", "performance review",
    "urgent request from ceo", "confidential document attached",
    "termination notice",

    # IT / Cloud / Email Storage Alerts
    "mailbox quota exceeded", "email quarantine", "storage full",
    "password expiration notice", "upgrade your storage",
    "action required: email sync", "microsoft 365 alert",
    "google workspace alert", "unauthorized login blocked",

    # Subscriptions / E-commerce Fake Renewals
    "subscription renewed", "auto-renewal notice",
    "cancel subscription", "billing error",
    "your prime membership", "antivirus subscription expired",
    "norton renewal", "mcafee invoice", "geek squad billing",

    # Cryptocurrency / Web3 Scams
    "crypto wallet frozen", "seed phrase required",
    "connect your wallet", "bitcoin giveaway",
    "airdrop claim", "unauthorized withdrawal",
    "validate your wallet",

    # Documents / Attachments
    "view document", "view secure document",
    "secure document", "document shared with you",
    "document requires your signature",
    "signature required", "review and sign",
    "download the document", "attached invoice",
    "attached statement", "protected document",
    "encrypted document",
    
    # Copyright & Social Media
    "copyright violation", "copyright infringement notice", "trademark violation",
    "your page will be unpublished", "community standards violation",
    "appeal this decision", "object to this decision", "copyright appeal form",
    "unusual activity on your page", "intellectual property claim",

    # Voicemail & E-Fax
    "new voicemail", "missed call from", "voice message attached",
    "fax received", "new e-fax document", "audio recording attached",
    "playback message", "listen to voicemail", "caller id",

    # Soft BEC / CEO Fraud (Conversational)
    "are you at your desk", "are you available", "i need a quick favor",
    "treat this as confidential", "discreet transaction",
    "purchase gift cards", "apple gift cards", "google play cards",
    "let me know when you are free", "urgent wire transfer",

    # Sextortion / Blackmail
    "i have recorded you", "your device was hacked", "pegasus spyware",
    "i know your password is", "pay in bitcoin", "send btc to this wallet",
    "video of you", "forwarding to your contacts", "your operating system has been hacked",

    # Legal, Gov & Tax Authority
    "court notice", "subpoena", "notice of appearance",
    "tax audit", "irs notification", "hmrc alert",
    "legal complaint against you", "lawsuit filed", "mandatory court attendance"
]

MACRO_DANGEROUS_KEYWORDS = [

    # Auto Execute
    "AutoExec",
    "AutoOpen",
    "AutoClose",
    "AutoNew",
    "Document_Open",
    "Document_Close",
    "Document_New",
    "Workbook_Open",
    "Workbook_BeforeClose",
    "Workbook_Activate",
    "Workbook_Deactivate",
    "Workbook_SheetActivate",
    "Workbook_SheetChange",

    # Command Execution
    "Shell",
    "ShellExecute",
    "Run",
    "Application.Run",
    "Execute",
    "Eval",
    "CallByName",

    # COM Objects
    "CreateObject",
    "GetObject",
    "WScript.Shell",
    "Shell.Application",
    "Scripting.FileSystemObject",
    "ADODB.Stream",
    "Excel.Application",
    "Word.Application",
    "Outlook.Application",

    # PowerShell / LOLBins
    "powershell",
    "cmd.exe",
    "wscript",
    "cscript",
    "mshta",
    "rundll32",
    "regsvr32",
    "wmic",
    "certutil",
    "bitsadmin",

    # Network
    "XMLHTTP",
    "MSXML2.XMLHTTP",
    "ServerXMLHTTP",
    "WinHttpRequest",
    "URLDownloadToFile",
    "InternetOpen",
    "InternetConnect",
    "InternetReadFile",
    "DownloadFile",

    # File System
    "FileCopy",
    "CopyFile",
    "MoveFile",
    "DeleteFile",
    "Kill",
    "MkDir",
    "RmDir",
    "SetAttr",
    "Open",
    "Close",
    "Print",
    "Write",
    "Put",
    "Get",
    "SaveAs",
    "SaveCopyAs",
    "CreateTextFile",
    "OpenTextFile",
    "WriteLine",

    # Registry
    "GetSetting",
    "SaveSetting",
    "DeleteSetting",
    "RegRead",
    "RegWrite",
    "RegDelete",

    # Environment
    "Environ",
    "ExpandEnvironmentStrings",
    "GetTempName",
    "SpecialFolders",
    "UserName",
    "ComputerName",

    # VBA Project Manipulation
    "VBProject",
    "VBComponents",
    "CodeModule",
    "AddFromString",
    "InsertLines",
    "DeleteLines",

    # Windows API
    "Declare PtrSafe",
    "Declare Function",
    "VirtualAlloc",
    "VirtualProtect",
    "WriteProcessMemory",
    "ReadProcessMemory",
    "CreateProcess",
    "CreateThread",
    "CreateRemoteThread",
    "WinExec",
    "LoadLibrary",
    "GetProcAddress",
    "CopyMemory",
    "RtlMoveMemory",

    # Obfuscation
    "Chr",
    "ChrW",
    "Asc",
    "Hex",
    "Base64",
    "StrReverse",
    "Replace",
    "Split",
    "Join",
    "Xor",
    "Mid",
    "Left",
    "Right",

    # Persistence
    "Startup",
    "StartupPath",
    "CurrentUser",
    "RunOnce",
    "RunServices",
    "Schedule.Service",
    "TaskScheduler",

]