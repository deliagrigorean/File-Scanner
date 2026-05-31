import hashlib
import os
import json
import pyzipper
import tempfile
import subprocess
import io

class AntivirusEngine:
    def __init__(self, sig_dir="signatures"):
        self.sig_dir = sig_dir
        self.whitelist = set()
        self.blacklist = {}
        self.string_rules = [] 
        self.byte_rules = [] 
        
        self.load_hashes()
        self.load_string_rules()
        self.load_byte_rules() 

    def load_hashes(self):
        hash_file = r"C:\Users\dg\Desktop\AntivirusProject\signatures\hashes.json"
        if not os.path.exists(hash_file): 
            return
        try:
            with open(hash_file, 'r') as f:
                data = json.load(f)
                self.whitelist = set(data.get("white_list", []))
                self.blacklist = data.get("black_list", {})
        except Exception as e: 
            pass

    def load_string_rules(self):
        rules_file = r"C:\Users\dg\Desktop\AntivirusProject\signatures\strings.json"
        if not os.path.exists(rules_file): 
            return
        try:
            with open(rules_file, 'r') as f:
                self.string_rules = json.load(f).get("rules", [])
        except Exception as e: 
            pass

    def load_byte_rules(self):
        rules_file = r"C:\Users\dg\Desktop\AntivirusProject\signatures\bytes.json"
        if not os.path.exists(rules_file): 
            return
        try:
            with open(rules_file, 'r') as f:
                self.byte_rules = json.load(f).get("rules", [])
        except Exception as e: 
            pass

    def calculate_sha256(self, filepath):
        sha256_hash = hashlib.sha256()
        try:
            with open(filepath, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            rezultat = sha256_hash.hexdigest()
            return rezultat
        except Exception as e: 
            return None

    def _scan_content_in_memory(self, filename, content):
        
        hash_in_ram = hashlib.sha256(content).hexdigest()
        
        if hash_in_ram in self.whitelist:
            return None 
        if hash_in_ram in self.blacklist:
            nume_virus = self.blacklist.get(hash_in_ram, "Unknown_Malware")
            return f"[MALWARE] Blacklist (în arhivă): {nume_virus} ({filename})"

        try:
            text_content = content.decode('utf-8', errors='ignore')
            for rule in self.string_rules:
                malicious_strings = rule.get("strings", {}) 
                all_found = all(text_content.count(s) >= c for s, c in malicious_strings.items())
                if all_found and malicious_strings:
                    return f"[SUSPICIOUS] Text malitios gasit in {filename}"
        except: pass

        for rule in self.byte_rules:
            hex_str = rule.get("hex", "")
            offset = rule.get("offset", "any")
            if not hex_str: continue
            try: sig_bytes = bytes.fromhex(hex_str)
            except: continue 
            
            if isinstance(offset, int) and content.startswith(sig_bytes, offset):
                return f"[MALWARE] Hex: {rule.get('name')} (in {filename})"
            elif offset == "any" and content.find(sig_bytes) != -1:
                return f"[MALWARE] Hex: {rule.get('name')} (in {filename})"
                
        return None

    def scan_strings(self, filepath):
        try:
            with open(filepath, 'r', errors='ignore') as f:
                content = f.read()
                for rule in self.string_rules:
                    rule_name = rule.get("name", "Unknown Rule")
                    malicious_strings = rule.get("strings", {}) 
                    all_found = True
                    found_counts = {}
                    
                    for search_string, exact_occurrences in malicious_strings.items():
                        count = content.count(search_string)
                        if count != exact_occurrences:
                            all_found = False
                            break 
                        found_counts[search_string] = count
                        
                    if all_found and malicious_strings:
                        details = ", ".join([f"'{k}' ({v} ori)" for k, v in found_counts.items()])
                        return f"{rule_name} -> Detalii: {details}"
        except Exception as e: 
            pass
            
        return None

    def scan_bytes(self, filepath):
        try:
            with open(filepath, 'rb') as f:
                content = f.read() 
                
                for rule in self.byte_rules:
                    rule_name = rule.get("name", "Unknown Byte Rule")
                    hex_string = rule.get("hex", "")
                    offset = rule.get("offset", "any")
                    
                    if not hex_string: continue
                    try: 
                        signature_bytes = bytes.fromhex(hex_string)
                    except ValueError: 
                        continue 
                    
                    if isinstance(offset, int):
                        if content.startswith(signature_bytes, offset): 
                            return rule_name
                    else:
                        if content.find(signature_bytes) != -1: 
                            return rule_name
        except Exception as e: 
            pass
            
        return None

    def detect_file_type(self, filepath):
        try:
            with open(filepath, 'rb') as f:
                header = f.read(8)
                
                if header.startswith(b'PK\x03\x04'):
                    return "OFFICE_ZIP"
                
                if header.startswith(b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1'):
                    return "MSI_OR_OLE"
                
                f.seek(0)
                content = f.read(51200) 
                if b'AutoIt v3' in content or b'AU3!EA06' in content:
                    return "AUTOIT"
                    
        except Exception as e: 
            pass
            
        return "UNKNOWN"

    def unpack_and_scan(self, filepath):
        file_type = self.detect_file_type(filepath)
        
        if file_type == "UNKNOWN":
            return None

        if file_type == "OFFICE_ZIP":
            try:
                infectii = []
                
                parole_comune = [None, b"infected", b"malware", b"virus", b"1234", b"password"]
                
                with pyzipper.AESZipFile(filepath, 'r') as archive:
                    for filename in archive.namelist():
                        content = None
                        
                        for parola in parole_comune:
                            try:
                                with archive.open(filename, pwd=parola) as f:
                                    content = f.read()
                                break 
                            except RuntimeError:
                                continue 
                        
                        if content is None:
                            return f"[WARNING] Arhivă parlată! Scanare interioară blocată."
                        
                        res = self._scan_content_in_memory(filename, content)
                        if res: infectii.append(res)
                        
                if infectii:
                    return f"[MALWARE] Container infectat! Viruși: {' | '.join(infectii)}"
                return f"[CLEAN] {file_type} sigur."
            except Exception as e: 
                return f"[ERROR] Eroare extragere ZIP: {e}"
            
        elif file_type == "AUTOIT":
            return f"[SUSPICIOUS/AUTOIT] Fișier AutoIt compilat detectat. Necesită decompiler extern."

        elif file_type == "MSI_OR_OLE":
            try:
                with tempfile.TemporaryDirectory() as temp_dir:
                    if os.name == 'nt':
                        abs_msi = os.path.abspath(filepath)
                        abs_out = os.path.abspath(temp_dir)
                        try:
                            subprocess.run(['msiexec', '/a', abs_msi, '/qb', f'TARGETDIR={abs_out}'], 
                                           check=True, capture_output=True)
                            
                            infectii_gasite = []
                            for root, dirs, files in os.walk(temp_dir):
                                for file in files:
                                    extracted_path = os.path.join(root, file)
                                    result = self.scan_file(extracted_path, is_extracted=True)
                                    
                                    if "[MALWARE]" in result or "[SUSPICIOUS]" in result:
                                        clean_result = result.split(']')[-1].strip()
                                        infectii_gasite.append(f"({file}: {clean_result})")
                            
                            if infectii_gasite:
                                detalii = " | ".join(infectii_gasite)
                                return f"[MALWARE] Container infectat! Viruși găsiți: {detalii}"
                            
                            return f"[CLEAN] MSI despachetat și toate fișierele interne sunt sigure."
                        except Exception as e:
                            return f"[WARNING] Nu am putut extrage automat fișierul MSI."
                    else:
                        return f"[WARNING] Extragerea MSI este suportată doar pe Windows."
            except Exception as e:
                return f"[ERROR] Eroare la despachetarea MSI: {str(e)}"
                
        return None

    def scan_file(self, filepath, is_extracted=False):
        if not os.path.exists(filepath):
            return "ERROR: File not found"

        file_hash = self.calculate_sha256(filepath)
        if not file_hash: 
            return "ERROR: Cannot read file"

        if file_hash in self.whitelist: 
            return f"[CLEAN] Whitelisted"
        if file_hash in self.blacklist: 
            nume_virus = self.blacklist.get(file_hash, "Unknown_Malware") 
            return f"[MALWARE] Blacklist: {nume_virus}"

        string_match = self.scan_strings(filepath)
        if string_match: 
            return f"[SUSPICIOUS] Text: {string_match}"

        byte_match = self.scan_bytes(filepath)
        if byte_match: 
            return f"[MALWARE] Hex: {byte_match}"

        if not is_extracted:
            unpack_match = self.unpack_and_scan(filepath)
            if unpack_match: 
                return unpack_match

        return f"[UNKNOWN] Fisier inofensiv."

    def scan_path(self, path):
        if os.path.isfile(path):
            return self.scan_file(path)
        elif os.path.isdir(path):
            rezultate = []
            for root, dirs, files in os.walk(path):
                for file in files:
                    full_path = os.path.join(root, file)
                    rezultat = self.scan_file(full_path)
                    rezultate.append(f"{full_path} -> {rezultat}")
            return "\n".join(rezultate)
        else:
            return "[!] Eroare: Calea nu există."