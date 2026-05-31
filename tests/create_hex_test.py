# Creăm un fișier cu semnătura "DEADBEEF" ascunsă în el
with open("test_hex_virus.bin", "wb") as f:
    f.write(b"Cod normal aici...")
    f.write(bytes.fromhex("DEADBEEF"))
    f.write(b"...mai mult cod normal.")
print("Fisierul de test a fost creat!")