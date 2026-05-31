import argparse
import os
from scanner import AntivirusEngine

def main():
    parser = argparse.ArgumentParser(description="My Custom Antivirus Engine")
    parser.add_argument("path", help="Calea către fișier sau folder")
    
    args = parser.parse_args()
    
    engine = AntivirusEngine(sig_dir="../signatures")

    print(f"[*] Antivirus Engine Initialized:")
    print(f"    -> {len(engine.whitelist) + len(engine.blacklist)} reguli Hash (Layer 1)")
    print(f"    -> {len(engine.string_rules)} reguli Strings (Layer 2)")
    print(f"    -> {len(engine.byte_rules)} reguli Bytes (Layer 3)\n")

    target_path = args.path
    
    print(f"[*] Incepere scanare pentru: {target_path}")
    print("-" * 60)
   
    rezultat = engine.scan_path(target_path)
    print(rezultat)
    
    print("-" * 60)
    print("[*] Scanare finalizata.")

if __name__ == "__main__":
    main()