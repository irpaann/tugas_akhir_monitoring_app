import joblib
import re
import os
import numpy as np
import pandas as pd
from models.rule_engine import check_rule_based

class SecurityEngine:
    def __init__(self):
        self.use_ml = True  
        self.occ_model = None
        self.scaler = None

        if self.use_ml:
            try:
                # Load Model dan Scaler hasil training 7.1
                self.occ_model = joblib.load(os.path.join('models', '7.2_model_isoforest_waf.pkl'))
                self.scaler = joblib.load(os.path.join('models', '7.2_scaler_waf.pkl'))
                print("✅ SecurityEngine: ML Mode (Isolation Forest 7.1) Active!")
            except Exception as e:
                print(f"❌ Error Load ML: {e}")
                self.use_ml = False

    def extract_features(self, status_code, payload, path, time_diff):
        raw_payload = str(payload) if pd.notna(payload) and str(payload).lower() != "none" else ""
        path_str = str(path).lower()
        
        # --- EKSTRAKSI FITUR (URUTAN HARUS SAMA DENGAN 7.7_datanumeriklatihan) ---
        # 1. status_code
        f_status = float(status_code)
        # 2. payload_length
        f_pay_len = float(len(raw_payload))
        # 3. special_char_count
        f_special = float(len(re.findall(r"[\'\;\(\)\[\]\<\>\=\+\-\-\{\}]", raw_payload)))
        # 4. non_alphanumeric_ratio
        f_ratio = float(len(re.findall(r'[^a-zA-Z0-9]', raw_payload)) / f_pay_len) if f_pay_len > 0 else 0.0
        # 5. has_sql_keywords
        f_sql = 1.0 if re.search(r'(select|insert|update|delete|union|--|#)', raw_payload, re.I) else 0.0
        # 6. has_html_tags
        f_html = 1.0 if re.search(r'(<script|alert\(|href=|<img)', raw_payload, re.I) else 0.0
        # 7. entropy
        import math
        from collections import Counter
        p, lns = Counter(raw_payload), float(len(raw_payload))
        f_entropy = -sum(count/lns * math.log(count/lns, 2) for count in p.values()) if lns > 0 else 0.0
        # 8. time_diff
        f_time = float(time_diff)
        # 9. is_login_path
        f_login = 1.0 if any(x in path_str for x in ['login', 'auth', 'signin']) else 0.0

        # KEMBALIKAN DALAM BENTUK LIST (URUTAN KRUSIAL!)
        return [f_status, f_pay_len, f_special, f_ratio, f_sql, f_html, f_entropy, f_time, f_login]

    def analyze(self, path, payload, ua, method, time_diff, status_code=200):
        raw_payload = str(payload) if pd.notna(payload) and str(payload).lower() != "none" else ""
        
        if self.use_ml:
            try:
                # 1. Ekstraksi fitur
                f_list = self.extract_features(status_code, raw_payload, path, time_diff)
                
                feature_names = [
                    'status_code', 'payload_length', 'special_char_count', 
                    'non_alphanumeric_ratio', 'has_sql_keywords', 'has_html_tags', 
                    'entropy', 'time_diff', 'is_login_path'
                ]
                
                # --- [DEBUG] TAMPILKAN HITUNGAN MANUAL KE TERMINAL ---
                print("\n" + "="*50)
                print("🔍 ML FEATURE EXTRACTION REPORT")
                print("="*50)
                for name, val in zip(feature_names, f_list):
                    print(f"{name.ljust(25)} : {val}")
                print("="*50)

                # 2. Buat DataFrame & Scaling
                X_new = pd.DataFrame([f_list], columns=feature_names)
                X_scaled = self.scaler.transform(X_new)
                
                # 3. Prediksi
                prediction = self.occ_model.predict(X_scaled)[0]
                raw_score = self.occ_model.decision_function(X_scaled)[0]
                
                # Hitung Score
                threat_score = max(0, min(100, round((0.5 - raw_score) * 100, 2)))

                if prediction == -1:
                    print(f"RESULT: 🛑 ANOMALY DETECTED (Score: {threat_score})")
                    return "Attack", "Anomaly Detected (ML Isolation Forest)", threat_score
                else:
                    print(f"RESULT: ✅ NORMAL (Score: {threat_score})")
                    return "Normal", "Request Aman (ML)", 0.0

            except Exception as e:
                import traceback
                print(f"\n[CRITICAL ML ERROR] : {e}")
                traceback.print_exc() 
                return "Error", f"ML Analysis Failed: {str(e)}", 0.0

        # Fallback Rule-Based (Opsional)
        alasan = check_rule_based(f"{path} {raw_payload}")
        if alasan: return "Attack", alasan, 90.0
        return "Normal", "Request Aman (Rule)", 0.0