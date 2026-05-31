# File-Scanner

* **Arhitectură de Detecție pe 4 Straturi:**
  * **Layer 1: Identificare Hash** Verificare instantanee a amprentelor SHA-256 (Whitelist/Blacklist).
  * **Layer 2: Strings** Analiză lexicală precisă (cu praguri exacte de apariție) pentru a prinde scripturi ofuscate.
  * **Layer 3: Hex Signatures** Inspecție profundă asemănătoare regulilor YARA (offset fix sau global scanning).
  * **Layer 4: Dynamic Unpacking** Recunoaște "Magic Bytes" și despachetează automat containere ZIP, MSI sau executabile ascunse.

*  **GUI Inteligent:** O interfață curată construită în `tkinter`, cu indicatori cromatici vizuali (🟢 Clean, 🟠 Warning, 🔴 Malware).

---

Acest motor a fost testat și calibrat folosind amenințări reale, respectând un flux strict de securitate operațională:
1. **Malware Samples:** Eșantioanele reale au fost preluate din platforma **MalwareBazaar**.
2. **Sandbox Environment:** Testarea s-a făcut într-o mașină virtuală izolată (Oracle VM / Windows 11).
3. **Izolarea Datelor:** Manipularea containerelor periculoase s-a făcut exclusiv prin terminal folosind **Far Manager**.
4. **Binary Forensics:** Extragerea payload-urilor (Layer 3 - Hex) a fost realizată folosind framework-ul de inginerie inversă **GView**.
