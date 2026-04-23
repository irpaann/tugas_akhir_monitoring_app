import sqlite3

# 1. SESUAIKAN DENGAN NAMA FILE DATABASE ANDA
DB_FILE = 'logs.db' 

# 2. SESUAIKAN DENGAN IP ANDA YANG TERBLOKIR 
# (Apakah 10.28.175.127 atau 10.79.125.127 seperti di log sebelumnya?)
MY_IP = '10.28.175.127' 

try:
    # Koneksi ke database
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    # Mengecek apakah IP ada di blacklist
    cursor.execute("SELECT * FROM blacklist_ip WHERE ip = ?", (MY_IP,))
    if cursor.fetchone():
        # Menghapus IP tersebut secara permanen dari tabel blacklist
        cursor.execute("DELETE FROM blacklist_ip WHERE ip = ?", (MY_IP,))
        conn.commit()
        print(f"✅ BERHASIL! IP {MY_IP} telah dihapus dari daftar blacklist dan dibebaskan.")
    else:
        print(f"⚠️ IP {MY_IP} tidak ditemukan di dalam blacklist.")

except Exception as e:
    print(f"❌ Terjadi kesalahan: {e}")
finally:
    if conn:
        conn.close()