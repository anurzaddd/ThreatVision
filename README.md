# 🧠 ThreatVision

> **اولین ابزار متن‌باز پیش‌بینی‌کننده‌ی تهدیدات شبکه با هوش مصنوعی**

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](http://makeapullrequest.com)

---

## 🔥 چرا ThreatVision؟

در دنیای امروز، ابزارهای امنیتی مثل Suricata یا Snort فقط بر اساس **امضا (Signature)** کار می‌کنند و حملات روز صفر (Zero-Day) را نمی‌شناسند. 
**ThreatVision** با استفاده از **یادگیری ماشین**، الگوهای غیرعادی را در لاگ‌های شبکه شناسایی کرده و **احتمال حمله در ۲۴ ساعت آینده** را پیش‌بینی می‌کند.

---

## ✨ ویژگی‌های منحصربه‌فرد

| ویژگی | توضیح |
|-------|-------|
| 🧠 **تشخیص ناهنجاری با Isolation Forest** | شناسایی حملات ناشناخته و روز صفر |
| 📊 **پیش‌بینی ریسک** | محاسبه‌ی درصد احتمال حمله در ۲۴ ساعت آینده |
| 🔄 **یادگیری مداوم** | مدل هر ساعت با لاگ‌های جدید بازآموزی می‌شود |
| 📱 **هشدار فوری** | ارسال اعلان به تلگرام، Slack یا ایمیل |
| 📦 **خروجی JSON** | یکپارچگی آسان با SIEMها (Splunk, Elastic) |
| 🚀 **سبک و سریع** | با حداقل منابع اجرا می‌شود |

---

## 🛠️ نصب و راه‌اندازی

### ۱. کلون کردن مخزن
```bash
git clone https://github.com/anurzaddd/ThreatVision.git
cd ThreatVision
