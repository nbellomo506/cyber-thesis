import math
import re
import pandas as pd

FEATURE_COLUMNS = [
    'length', 'entropy', 'special_chars_ratio', 'upper_case_ratio', 'num_digits', 'longest_word',
    'num_semicolons', 'num_pipes', 'num_backticks', 'num_plus', 'num_dollars', 
    'num_brackets', 'num_quotes', 'num_parenthesis', 'num_commas',
    'has_encoded', 'has_iex', 'has_bypass', 'has_web_request', 'has_dll_ext', 
    'has_api_calls', 'has_add_type', 'has_rundll32', 'has_creds_theft', 'has_persistence',
    'danger_density'
]

def calculate_entropy(text):
    if not text or len(text) == 0: return 0
    probs = [text.count(c) / len(text) for c in set(text)]
    return -sum(p * math.log(p, 2) for p in probs)

def get_longest_word(text):
    words = re.findall(r'\w+', text)
    return max(len(w) for w in words) if words else 0

def extract_features_dict(command):
    low_cmd = command.lower()
    f = {}
    f['length'] = len(command)
    f['entropy'] = calculate_entropy(command)
    f['special_chars_ratio'] = sum(1 for c in command if not c.isalnum() and not c.isspace()) / len(command) if len(command)>0 else 0
    f['upper_case_ratio'] = sum(1 for c in command if c.isupper()) / len(command) if len(command)>0 else 0
    f['num_digits'] = sum(c.isdigit() for c in command)
    f['longest_word'] = get_longest_word(command)
    f['num_semicolons'] = command.count(';')
    f['num_pipes'] = command.count('|')
    f['num_backticks'] = command.count('`')
    f['num_plus'] = command.count('+')
    f['num_dollars'] = command.count('$')
    f['num_brackets'] = sum(command.count(c) for c in ['[', ']', '{', '}'])
    f['num_quotes'] = command.count("'") + command.count('"')
    f['num_parenthesis'] = command.count('(') + command.count(')')
    f['num_commas'] = command.count(',')
    f['has_encoded'] = 1 if any(k in low_cmd for k in ['-enc', 'base64', 'encodedcommand']) else 0
    f['has_iex'] = 1 if any(k in low_cmd for k in ['iex', 'invoke-expression', 'i`ex']) else 0
    f['has_bypass'] = 1 if any(k in low_cmd for k in ['bypass', '-ep', 'unrestricted']) else 0
    f['has_web_request'] = 1 if any(k in low_cmd for k in ['http', 'download', 'webclient', 'iwr']) else 0
    f['has_dll_ext'] = 1 if '.dll' in low_cmd else 0
    f['has_api_calls'] = 1 if any(k in low_cmd for k in ['kernel32', 'virtualalloc', 'writeprocessmemory', 'ntdll', 'loadlibrary']) else 0
    f['has_add_type'] = 1 if 'add-type' in low_cmd else 0
    f['has_rundll32'] = 1 if 'rundll32' in low_cmd else 0
    f['has_creds_theft'] = 1 if any(k in low_cmd for k in ['mimikatz', 'sekurlsa', 'lsadump']) else 0
    f['has_persistence'] = 1 if any(k in low_cmd for k in ['schtasks', 'scheduledtask', 'set-itemproperty']) else 0
    danger_signals = [c for c in f if c.startswith('has_')]
    f['danger_density'] = sum(f[sig] for sig in danger_signals)
    return {col: f[col] for col in FEATURE_COLUMNS}