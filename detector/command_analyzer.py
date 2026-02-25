import base64
import re

class MaliciousAnalyzer:
    def __init__(self):
        # Parole chiave sospette che indicano un attacco fileless
        self.suspicious_keywords = ["iex", "invoke-expression", "-enc", "-encodedcommand", "hidden", "bypass", "downloadstring"]

    def decode_base64(self, text):
        """Cerca e decodifica stringhe Base64 all'interno del testo."""
        # Regex per trovare stringhe che sembrano Base64 (lunghezza min 20 caratteri)
        b64_pattern = r'[A-Za-z0-9+/]{20,}={0,2}'
        matches = re.findall(b64_pattern, text)
        
        decoded_parts = []
        for match in matches:
            try:
                # Prova a decodificare
                decoded = base64.b64decode(match).decode('utf-16le', errors='ignore')
                # Se la decodifica non ha senso, prova con utf-8
                if not any(c.isalpha() for c in decoded):
                    decoded = base64.b64decode(match).decode('utf-8', errors='ignore')
                decoded_parts.append(decoded)
            except:
                continue
        return decoded_parts

    def analyze_string(self, raw_data):
        """Analizza profondamente la stringa e restituisce un report."""
        findings = {
            "is_suspicious": False,
            "reason": [],
            "decoded_content": ""
        }
        
        data_lower = raw_data.lower()
        
        # 1. Controllo parole chiave nel comando originale
        for kw in self.suspicious_keywords:
            if kw in data_lower:
                findings["is_suspicious"] = True
                findings["reason"].append(f"Parola chiave sospetta: {kw}")

        # 2. Controllo e decodifica Base64
        decoded_payloads = self.decode_base64(raw_data)
        if decoded_payloads:
            findings["decoded_content"] = " | ".join(decoded_payloads)
            findings["is_suspicious"] = True
            findings["reason"].append("Rilevata codifica Base64 offuscata")
            
            # Analizziamo anche il contenuto decodificato per parole chiave
            for payload in decoded_payloads:
                for kw in self.suspicious_keywords:
                    if kw in payload.lower():
                        findings["reason"].append(f"Payload decodificato contiene: {kw}")

        return findings