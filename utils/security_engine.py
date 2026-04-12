import joblib
import re
import os
import numpy as np
import pandas as pd
import math
from collections import Counter
from models.rule_engine import check_rule_based

class SecurityEngine:
    def __init__(self, mode=""):  
        """
        mode: 'ML', 'RULE', atau 'NONE'. 
        Sistem bersifat kaku: Jika ML gagal, deteksi mati (tidak lempar ke RULE).
        """
        self.mode = mode.upper() if mode else "NONE"
        self.occ_model = None
        self.scaler = None

        if self.mode == "ML":
            try:
                self.occ_model = joblib.load(os.path.join('models', '7.2_model_isoforest_waf.pkl'))
                self.scaler = joblib.load(os.path.join('models', '7.2_scaler_waf.pkl'))
                print(f" SecurityEngine: MODE ML AKTIF")
            except Exception as e:
                # KAKU: Jika gagal load, mode dimatikan, tidak dioper ke RULE
                print(f"❌ Error Load ML: {e}. Deteksi dinonaktifkan (ERROR STATE).")
                self.mode = "NONE" 
        
        elif self.mode == "RULE":
            print("⚙️  SecurityEngine: MODE RULE-BASED AKTIF")
        
        else:
            # Jika user input 'NONE', atau typo seperti 'MLL', atau kosong
            self.mode = "NONE"
            print("⚠️ SecurityEngine: MODE POLOS (Deteksi Dinonaktifkan/Typo Detected!)")
            

    def extract_features(self, status_code, payload, path, time_diff):
        raw_payload = str(payload) if pd.notna(payload) and str(payload).lower() != "none" else ""
        path_str = str(path).lower()
        
        # --- EKSTRAKSI FITUR ---
        f_status = float(status_code)
        f_pay_len = float(len(raw_payload))
        f_special = float(len(re.findall(r"[\'\;\(\)\[\]\<\>\=\+\-\-\{\}]", raw_payload)))
        f_ratio = float(len(re.findall(r'[^a-zA-Z0-9]', raw_payload)) / f_pay_len) if f_pay_len > 0 else 0.0
        f_sql = 1.0 if re.search(r'(select|insert|update|delete|union|--|#)', raw_payload, re.I) else 0.0
        f_html = 1.0 if re.search(r'(<script|alert\(|href=|<img)', raw_payload, re.I) else 0.0
        
        p, lns = Counter(raw_payload), float(len(raw_payload))
        f_entropy = -sum(count/lns * math.log(count/lns, 2) for count in p.values()) if lns > 0 else 0.0
        
        f_time = float(time_diff)
        f_login = 1.0 if any(x in path_str for x in ['login', 'auth', 'signin']) else 0.0

        return [f_status, f_pay_len, f_special, f_ratio, f_sql, f_html, f_entropy, f_time, f_login]

    def analyze(self, path, payload, ua, method, time_diff, status_code=200):
        raw_payload = str(payload) if pd.notna(payload) and str(payload).lower() != "none" else ""

        # --- LOGIKA EKSKLUSIF & STATIS ---

        # 1. JIKA MODE ML
        if self.mode == "ML":
            if self.occ_model and self.scaler:
                try:
                    f_list = self.extract_features(status_code, raw_payload, path, time_diff)
                    feature_names = [
                        'status_code', 'payload_length', 'special_char_count', 
                        'non_alphanumeric_ratio', 'has_sql_keywords', 'has_html_tags', 
                        'entropy', 'time_diff', 'is_login_path'
                    ]
                    
                    # Debug report tetap muncul
                    print("\n" + "═"*50)
                    print(f"🔍 ML FEATURE EXTRACTION REPORT")
                    print("─"*50)
                    for name, val in zip(feature_names, f_list):
                        print(f"{name.ljust(25)} : {val}")
                    print("─"*50)

                    X_new = pd.DataFrame([f_list], columns=feature_names)
                    X_scaled = self.scaler.transform(X_new)
                    
                    prediction = self.occ_model.predict(X_scaled)[0]
                    raw_score = self.occ_model.decision_function(X_scaled)[0]
                    threat_score = max(0, min(100, round((0.5 - raw_score) * 100, 2)))

                    if prediction == -1:
                        print(f"RESULT  : 🛑 ANOMALY DETECTED ({threat_score}%)")
                        return "Attack", "Anomaly Detected (ML)", threat_score
                    else:
                        print(f"RESULT  : ✅ NORMAL (0.0%)")
                        return "Normal", "Request Aman (ML)", 0.0
                except Exception as e:
                    print(f"⚠️ Error dalam Eksekusi ML: {e}")
                    return "Normal", "ML Execution Error", 0.0
            else:
                return "Normal", "ML Mode Active but Model not Loaded", 0.0

        # 2. JIKA MODE RULE
        elif self.mode == "RULE":
            alasan = check_rule_based(f"{path} {raw_payload}")
            if alasan:
                print(f"\n🛡️  RULE-BASED: 🛑 ATTACK! ({alasan})")
                return "Attack", alasan, 90.0
            return "Normal", "Request Aman (Rule)", 0.0

        # 3. JIKA MODE NONE / TYPO
        else:
            # Tidak melakukan pengecekan apapun
            return "Normal", "Mode Polos: Keamanan Diabaikan", 0.0