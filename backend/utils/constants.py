"""Shared constants for the detection engine.

Everything here is a *project assumption* meant for education. In a real
deployment these lists would come from threat intelligence and be reviewed
regularly.
"""

# Fictional brands used in the synthetic dataset. Real organisations would
# maintain their own list of brands that attackers commonly impersonate.
BRAND_NAMES = ["examplebank", "examplepay", "exampleshop", "examplecloud", "examplemail"]

# Domains we consider "known good" for the fictional brands above.
# (An allow-list like this is how real gateways avoid flagging your own domains.)
TRUSTED_DOMAINS = {"examplebank.example.com", "exampleshop.example.com"}

# Real shorteners (pattern matching only - we never visit them) plus two
# fictional ones used by the synthetic dataset.
SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "short.example", "tiny.example",
}

# Words that often appear in credential-harvesting URLs. Matched as whole
# tokens (split on non-alphanumerics) to reduce accidental matches.
URL_KEYWORDS = [
    "login", "signin", "verify", "verification", "account", "secure", "update",
    "confirm", "password", "banking", "wallet", "suspend", "unlock", "invoice",
    "payment", "reset", "billing", "recover",
]

# Keywords in sender domains / local parts (weak signals on their own).
SENDER_DOMAIN_KEYWORDS = [
    "verify", "account", "login", "secure", "security", "alert", "update",
    "billing", "helpdesk", "confirm", "signin",
]

# Country-code style two-level suffixes so "bbc.co.uk" is not miscounted
# as having a subdomain. Deliberately small.
TWO_LEVEL_SUFFIXES = {"co.uk", "org.uk", "ac.uk", "com.au", "co.in", "co.jp", "com.br"}

# Character swaps commonly used in lookalike domains (0->o, 1->l, ...).
LEET_MAP = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "@": "a", "$": "s"})

# Attachment extension groups
EXECUTABLE_EXTENSIONS = {".exe", ".scr", ".bat", ".cmd", ".com", ".pif", ".msi", ".jar"}
SCRIPT_EXTENSIONS = {".js", ".vbs", ".ps1", ".hta", ".wsf", ".sh"}
ARCHIVE_EXTENSIONS = {".zip", ".rar", ".7z", ".iso", ".img", ".gz"}
MACRO_EXTENSIONS = {".docm", ".xlsm", ".pptm"}
HTML_EXTENSIONS = {".html", ".htm"}
DOCUMENT_EXTENSIONS = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".jpg", ".jpeg", ".png", ".csv"}

# Input limits (defensive: never process unbounded input)
MAX_BODY_CHARS = 200_000
MAX_URLS = 50
MAX_EML_BYTES = 1_000_000
