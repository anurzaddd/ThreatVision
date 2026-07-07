#!/usr/bin/env python3
"""
ThreatVision - AI-Powered Predictive Threat Detection
Author: Amir Hossein Nourzadeh
License: MIT
"""

import json
import time
import random
import logging
from datetime import datetime, timedelta
from collections import defaultdict
import requests
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

# =============================================
# تنظیمات پیش‌فرض (قابل تغییر توسط کاربر)
# =============================================
CONFIG = {
    "log_file": "network_logs.json",   # فایل ورودی لاگ‌ها (فرضاً توسط فایروال تولید شده)
    "output_file": "threat_report.json",
    "telegram_token": "YOUR_BOT_TOKEN",
    "telegram_chat_id": "YOUR_CHAT_ID",
    "anomaly_threshold": 0.75,          # آستانه‌ی هشدار (۰ تا ۱)
    "prediction_window": 24,            # پنجره‌ی پیش‌بینی (ساعت)
    "model_retrain_interval": 3600      # بازآموزی مدل هر چند ثانیه
}

# تنظیم لاگ‌گیری
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(message)s")

class ThreatPredictor:
    def __init__(self):
        self.model = None
        self.scaler = StandardScaler()
        self.feature_history = []
        self.last_train_time = None

    def extract_features(self, log_entry):
        """
        استخراج ویژگی‌های عددی از یک لاگ شبکه
        ورودی: یک دیکشنری شامل src_ip, dst_ip, port, protocol, bytes_sent, ...
        خروجی: لیستی از اعداد (ویژگی‌های عددی)
        """
        features = []
        # ۱. تعداد درخواست‌های غیرمعمول (مثلاً به پورت‌های بالا)
        features.append(1 if log_entry.get("dst_port", 0) > 1024 else 0)
        # ۲. حجم داده‌های ارسالی (نرمال‌سازی نمی‌کنیم، خود مدل انجام می‌دهد)
        features.append(log_entry.get("bytes_sent", 0) / 1000.0)  # کیلوبایت
        # ۳. تعداد پکت‌های دریافتی
        features.append(log_entry.get("packets", 0))
        # ۴. تعداد تلاش‌های ناموفق (مثلاً خطاهای احراز هویت)
        features.append(log_entry.get("failed_attempts", 0))
        # ۵. زمان (ساعت روز) به صورت سینوسی برای تشخیص الگوهای روزانه
        hour = datetime.fromisoformat(log_entry["timestamp"]).hour
        features.append(np.sin(2 * np.pi * hour / 24))
        return features

    def train_model(self, logs):
        """آموزش مدل Isolation Forest روی لاگ‌های اخیر"""
        if len(logs) < 50:
            logging.warning("داده‌ی کافی برای آموزش مدل وجود ندارد.")
            return

        feature_matrix = [self.extract_features(log) for log in logs]
        # استانداردسازی داده‌ها
        scaled = self.scaler.fit_transform(feature_matrix)
        # آموزش مدل
        self.model = IsolationForest(contamination=0.05, random_state=42)
        self.model.fit(scaled)
        self.last_train_time = datetime.now()
        logging.info(f"✅ مدل با {len(logs)} نمونه آموزش داده شد.")

    def predict(self, log_entry):
        """پیش‌بینی میزان غیرعادی بودن یک لاگ جدید"""
        if self.model is None:
            return 0.0

        features = self.extract_features(log_entry)
        scaled = self.scaler.transform([features])
        score = self.model.decision_function(scaled)[0]
        # تبدیل به عدد بین ۰ و ۱ (۱ یعنی غیرعادی‌ترین)
        anomaly_score = 1 / (1 + np.exp(-score))  # سیگموئید
        return anomaly_score

    def generate_prediction(self, recent_logs):
        """تولید گزارش پیش‌بینی بر اساس لاگ‌های اخیر"""
        if len(recent_logs) < 10:
            return {"status": "insufficient_data", "message": "داده‌ی کافی برای پیش‌بینی وجود ندارد."}

        # میانگین ناهنجاری‌های اخیر
        scores = [self.predict(log) for log in recent_logs[-100:]]
        avg_anomaly = np.mean(scores) if scores else 0

        # پیش‌بینی احتمال حمله در ۲۴ ساعت آینده
        risk = min(1.0, avg_anomaly * 1.5)  # ساده‌سازی شده

        # تشخیص الگوهای خاص
        alerts = []
        if risk > CONFIG["anomaly_threshold"]:
            alerts.append(f"🚨 خطر بالا: {risk*100:.1f}% احتمال حمله در {CONFIG['prediction_window']} ساعت آینده.")
            # پیشنهاد اقدام
            alerts.append("🛡️ اقدام پیشنهادی: کش ARP را پاک کنید و لاگ‌های فایروال را بررسی نمایید.")
        else:
            alerts.append(f"✅ سطح خطر: {risk*100:.1f}% - شبکه در وضعیت عادی است.")

        return {
            "timestamp": datetime.now().isoformat(),
            "risk_score": float(risk),
            "avg_anomaly": float(avg_anomaly),
            "alerts": alerts,
            "window_hours": CONFIG["prediction_window"],
            "samples_analyzed": len(recent_logs)
        }

def load_sample_logs():
    """تولید لاگ‌های نمونه برای تست (در محیط واقعی از فایل یا Syslog استفاده کنید)"""
    logs = []
    base_time = datetime.now() - timedelta(hours=1)
    for i in range(100):
        log = {
            "timestamp": (base_time + timedelta(seconds=i*30)).isoformat(),
            "src_ip": f"192.168.1.{random.randint(2, 254)}",
            "dst_ip": f"10.0.0.{random.randint(1, 10)}",
            "dst_port": random.choice([80, 443, 22, 3389, random.randint(5000, 6000)]),
            "protocol": random.choice(["TCP", "UDP"]),
            "bytes_sent": random.randint(100, 50000),
            "packets": random.randint(1, 500),
            "failed_attempts": random.randint(0, 10)
        }
        logs.append(log)
    return logs

def main():
    print("="*60)
    print("🧠 ThreatVision - پیش‌بینی‌کننده‌ی هوشمند تهدیدات شبکه")
    print("="*60 + "\n")

    predictor = ThreatPredictor()
    
    # بارگذاری لاگ‌های نمونه (در محیط واقعی از فایل یا ورودی استاندارد استفاده می‌شود)
    logs = load_sample_logs()
    
    # آموزش اولیه
    predictor.train_model(logs)
    
    # هر چند ثانیه یک بار پیش‌بینی جدید انجام بده
    try:
        while True:
            if predictor.model is not None:
                prediction = predictor.generate_prediction(logs)
                print(json.dumps(prediction, indent=2, ensure_ascii=False))
                
                # ذخیره در فایل
                with open(CONFIG["output_file"], "w") as f:
                    json.dump(prediction, f, indent=2, ensure_ascii=False)
                
                # ارسال به تلگرام در صورت خطر بالا
                if prediction.get("risk_score", 0) > CONFIG["anomaly_threshold"]:
                    msg = f"🚨 پیش‌بینی تهدید: {prediction['alerts'][0]}"
                    # requests.post(...)  # اگر تلگرام تنظیم شده باشد
            else:
                print("⏳ در حال انتظار برای داده‌های کافی...")
            
            time.sleep(60)  # هر دقیقه یک بار
    except KeyboardInterrupt:
        print("\n🔻 خروج از برنامه.")

if __name__ == "__main__":
    main()
