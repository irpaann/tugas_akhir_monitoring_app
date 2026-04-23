import joblib
import re
import os
import numpy as np
import pandas as pd
import math
from collections import Counter
from models.rule_engine import check_rule_based

class SecurityEngine:
    def __init__(self, mode="ML"):  
        self.mode = mode.upper() if mode else "NONE"
        
        self.occ_model = None
        self.scaler = None
        self.rf_model = None
        self.rf_columns = None

        if self.mode == "ML":
            try:
                # 1. Load Anomaly Detection Models
                self.occ_model = joblib.load(os.path.join('models/occ_models', '8.0_model_isoforest_waf.pkl'))
                self.scaler = joblib.load(os.path.join('models/occ_models', '8.0_scaler_waf.pkl'))
                
                # 2. Load Classification Models (Random Forest V6)
                self.rf_model = joblib.load(os.path.join('models/rf_models', 'model_random_forest_AttacksOnly_V7.pkl'))
                self.rf_columns = joblib.load(os.path.join('models/rf_models', 'model_columns_AttacksOnly_V7.pkl'))
                
                print(f"✅ SecurityEngine: MODE ML AKTIF (OCC & RF Loaded)")
            except Exception as e:
                print(f"❌ Error Load ML: {e}. Deteksi dinonaktifkan (ERROR STATE).")
                self.mode = "NONE" 
        
        elif self.mode == "RULE":
            print("⚙️  SecurityEngine: MODE RULE-BASED AKTIF")
        
        else:
            self.mode = "NONE"
            print("⚠️ SecurityEngine: MODE POLOS (Deteksi Dinonaktifkan/Typo Detected!)")
            
    # ---> FUNGSI LAMA UNTUK ISOLATION FOREST (TETAP DIPERTAHANKAN)
    def extract_features(self, status_code, payload, path, time_diff):
        raw_payload = str(payload) if pd.notna(payload) and str(payload).lower() != "none" else ""
        path_str = str(path).lower()
        
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

    # ---> FUNGSI BARU KHUSUS UNTUK 18 FITUR RANDOM FOREST V6
    def extract_rf_features(self, payload, path, time_diff):
        raw_payload = str(payload).lower() if pd.notna(payload) and str(payload).lower() != "none" else ""
        path_str = str(path).lower()
        full_str = f"{path_str} {raw_payload}"

        f_payload_length = float(len(raw_payload))
        f_dot_count = float(full_str.count('.'))
        f_total_slash = float(full_str.count('/'))
        f_total_backslash = float(full_str.count('\\'))
        f_percent_count = float(full_str.count('%'))
        f_is_encoded = 1.0 if f_percent_count > 0 else 0.0
        f_double_dot_count = float(full_str.count('..'))
        
        sensitive_words = ['etc', 'passwd', 'shadow', 'boot.ini', 'win.ini', 'cmd.exe', 'system32']
        f_has_sensitive_word = 1.0 if any(w in full_str for w in sensitive_words) else 0.0
        
        non_alphanum = len(re.findall(r'[^a-zA-Z0-9\s]', raw_payload))
        f_non_alphanum_ratio = float(non_alphanum / f_payload_length) if f_payload_length > 0 else 0.0

        # Karena ini diproses per-request, fitur Brute Force diset ke nilai default/stateless
        f_request_count = 1.0 
        f_unique_payload_count = 1.0
        f_status_401_count = 0.0
        f_avg_time_diff = float(time_diff)
        f_status_401_ratio = 0.0

        f_special_char_count = float(len(re.findall(r"[\'\;\(\)\[\]\<\>\=\+\-\-\{\}]", raw_payload)))
        
        keywords = ['select', 'insert', 'update', 'delete', 'union', 'drop', 'script', 'alert', 'onerror', 'onload']
        f_keyword_count = float(sum(1 for k in keywords if k in raw_payload))
        
        f_space_count = float(raw_payload.count(' ') + raw_payload.count('%20'))
        f_digit_count = float(len(re.findall(r'\d', raw_payload)))

        # Format sebagai dictionary agar mudah diubah ke DataFrame
        return {
            'payload_length': f_payload_length,
            'dot_count': f_dot_count,
            'total_slash': f_total_slash,
            'total_backslash': f_total_backslash,
            'percent_count': f_percent_count,
            'is_encoded': f_is_encoded,
            'double_dot_count': f_double_dot_count,
            'has_sensitive_word': f_has_sensitive_word,
            'non_alphanum_ratio': f_non_alphanum_ratio,
            'request_count': f_request_count,
            'unique_payload_count': f_unique_payload_count,
            'status_401_count': f_status_401_count,
            'avg_time_diff': f_avg_time_diff,
            'status_401_ratio': f_status_401_ratio,
            'special_char_count': f_special_char_count,
            'keyword_count': f_keyword_count,
            'space_count': f_space_count,
            'digit_count': f_digit_count
        }

    def analyze(self, path, payload, ua, method, time_diff, status_code=200):
        raw_payload = str(payload) if pd.notna(payload) and str(payload).lower() != "none" else ""
        time_diff_float = float(time_diff)

        # =================================================================
        # PRE-PROCESSING (FEATURE ENGINEERING)
        # Sah dalam metodologi ML untuk menormalkan data yang kosong/ekstrem
        # =================================================================
        if time_diff_float == 0.0 or time_diff_float > 30.0:
            time_diff_float = 5.0

        if self.mode == "ML":
            if self.occ_model and self.scaler:
                try:
                    f_list = self.extract_features(status_code, raw_payload, path, time_diff_float)
                    feature_names = [
                        'status_code', 'payload_length', 'special_char_count', 
                        'non_alphanumeric_ratio', 'has_sql_keywords', 'has_html_tags', 
                        'entropy', 'time_diff', 'is_login_path'
                    ]
                    
                    X_new = pd.DataFrame([f_list], columns=feature_names)
                    X_scaled = self.scaler.transform(X_new)
                    
                    # =================================================================
                    # TAHAP 1: MURNI ISOLATION FOREST (ANOMALY DETECTION)
                    # =================================================================
                    prediction = self.occ_model.predict(X_scaled)[0]
                    raw_score = self.occ_model.decision_function(X_scaled)[0]
                    threat_score = max(0, min(100, round((0.5 - raw_score) * 100, 2)))

                    print(f"\n🔍 [WAF-ML] {method} {path} | Jeda: {time_diff_float:.2f}s")
                    print(f" ├─ OCC Score : {raw_score:.3f} (Batas < -0.050 = Anomali)")

                    # Tuning Threshold: Memberikan toleransi matematis 
                    if raw_score < -0.050:
                        print(f" ├─ Tahap 1 (OCC) : 🛑 ANOMALI (Threat: {threat_score}%)")
                        
                        # =================================================================
                        # TAHAP 2: MURNI RANDOM FOREST (KLASIFIKASI SERANGAN)
                        # =================================================================
                        attack_category_name = "Unknown Anomaly"
                        if self.rf_model is not None and self.rf_columns is not None:
                            try:
                                rf_features_dict = self.extract_rf_features(raw_payload, path, time_diff_float)
                                X_rf = pd.DataFrame([rf_features_dict])[self.rf_columns]
                                rf_prediction = self.rf_model.predict(X_rf)[0]
                                
                                label_mapping = {
                                    1: "Path Traversal",
                                    2: "Brute Force",
                                    3: "SQL Injection",
                                    4: "Cross-Site Scripting (XSS)"
                                }
                                attack_category_name = label_mapping.get(rf_prediction, f"Tipe {rf_prediction}")
                                
                                print(f" └─ Tahap 2 (RF)  : 🎯 {attack_category_name.upper()}")
                                
                            except Exception as rf_err:
                                print(f" └─ Error RF      : ⚠️ {rf_err}")
                        
                        return "Attack", f"Anomaly: {attack_category_name}", threat_score
                    else:
                        print(f" └─ Tahap 1 (OCC) : ✅ NORMAL (Aman)")
                        return "Normal", "Request Aman (ML)", 0.0
                
                except Exception as e:
                    print(f"⚠️ Error Eksekusi ML: {e}")
                    return "Normal", "ML Execution Error", 0.0
            else:
                return "Normal", "Model ML Belum Dimuat", 0.0

        # =================================================================
        # MODE PEMBANDING UNTUK PENELITIAN: MURNI RULE-BASED
        # =================================================================
        elif self.mode == "RULE":
            alasan = check_rule_based(f"{path} {raw_payload}")
            if alasan:
                print(f"\n🛡️ [WAF-RULE] 🛑 ATTACK! ({alasan})")
                return "Attack", alasan, 90.0
            
            print(f"\n🛡️ [WAF-RULE] ✅ NORMAL (Aman)")
            return "Normal", "Request Aman (Rule)", 0.0

        else:
            return "Normal", "Mode Polos", 0.0