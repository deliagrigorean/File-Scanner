import tkinter as tk
from tkinter import filedialog, messagebox
from scanner import AntivirusEngine

class AntivirusGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("🛡️ Sentinel Antivirus Engine")
        self.root.geometry("600x450")
        self.root.configure(bg="#1e1e2f") 
        
        
        try:
            self.engine = AntivirusEngine()
        except Exception as e:
            messagebox.showerror("Eroare", f"Nu am putut încărca motorul:\n{e}")
            self.engine = None
            
        
        self.header_frame = tk.Frame(root, bg="#29293d", pady=20)
        self.header_frame.pack(fill="x")
        
        self.label_title = tk.Label(self.header_frame, text="Fisier scanner", font=("Segoe UI", 20, "bold"), bg="#29293d", fg="#00d2ff")
        self.label_title.pack()
        

        self.body_frame = tk.Frame(root, bg="#1e1e2f", pady=30)
        self.body_frame.pack(expand=True, fill="both")
        
        self.btn_select = tk.Button(self.body_frame, text="📂 Selectează Fișier / Arhivă", command=self.select_file, 
                                    width=30, height=2, bg="#3d3d5c", fg="white", font=("Segoe UI", 11, "bold"), 
                                    relief="flat", activebackground="#4d4d73", activeforeground="white", cursor="hand2")
        self.btn_select.pack(pady=10)
        
        self.lbl_path = tk.Label(self.body_frame, text="Niciun fișier selectat.", bg="#1e1e2f", fg="#808099", font=("Consolas", 9), wraplength=550)
        self.lbl_path.pack(pady=5)
        
        self.btn_scan = tk.Button(self.body_frame, text="⚡ SCANEAZĂ ACUM", command=self.scan_file, 
                                  width=25, height=2, bg="#4CAF50", fg="white", font=("Segoe UI", 12, "bold"), 
                                  relief="flat", activebackground="#45a049", activeforeground="white", cursor="hand2", state="disabled")
        self.btn_scan.pack(pady=20)
        
        self.result_frame = tk.Frame(root, bg="#191926", pady=15)
        self.result_frame.pack(fill="x", side="bottom")
        
        self.lbl_status = tk.Label(self.result_frame, text="Așteptare fișier...", font=("Segoe UI", 12, "bold"), bg="#191926", fg="#808099", wraplength=550)
        self.lbl_status.pack()
        
        self.selected_path = None

    def select_file(self):
        filepath = filedialog.askopenfilename(title="Alege un fișier sau o arhivă")
        if filepath:
            self.selected_path = filepath
            self.lbl_path.config(text=filepath)
            self.lbl_status.config(text="Fișier încărcat. Gata de scanare.", fg="#00d2ff")
            
            self.btn_scan.config(state="normal", bg="#00cc66") 

    def scan_file(self):
        if not self.selected_path or not self.engine:
            return
            
        
        self.lbl_status.config(text="⚙️ Se analizează în profunzime...", fg="#ffcc00")
        self.btn_scan.config(bg="#3d3d5c")
        self.root.update() 
        
        
        rezultat = self.engine.scan_path(self.selected_path)
        
        
        if "[MALWARE]" in rezultat or "Blacklist" in rezultat:
            self.lbl_status.config(text=f"🛑 {rezultat}", fg="#ff4d4d")
            self.btn_scan.config(bg="#ff4d4d") 
        elif "[SUSPICIOUS]" in rezultat or "[WARNING]" in rezultat:
            self.lbl_status.config(text=f"⚠️ {rezultat}", fg="#ff9900")
            self.btn_scan.config(bg="#ff9900") 
        else:
            self.lbl_status.config(text=f"✅ {rezultat}", fg="#00cc66")
            self.btn_scan.config(bg="#00cc66") 

if __name__ == "__main__":
    root = tk.Tk()
    app = AntivirusGUI(root)
    root.mainloop()