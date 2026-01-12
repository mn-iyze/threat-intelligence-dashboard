# 🛡 Personal Threat Intelligence Dashboard

A lightweight **personal threat intelligence dashboard** built with Python and Streamlit.
It helps assess **digital identity risk** and **domain/IP reputation** using open threat-intelligence sources.

---

## 🔍 Features

### 📧 Identity Risk (Demo)
- Email / account risk visualization
- Designed for Have I Been Pwned integration (paid API required)
- Currently uses demo risk scoring

### 🌐 Domain & IP Reputation
- Live VirusTotal API integration
- Detects malicious activity, ASN owner, country, and reputation
- Blocks private IP ranges automatically

### 📊 Security-Focused UI
- Risk indicators and metrics
- Confidence bar visualization
- SOC-style layout

---

## 🧠 Why This Project?

This project demonstrates:
- Practical threat intelligence concepts
- Secure API handling using environment variables
- Defensive coding practices
- Data visualization for cybersecurity use cases

---

## 🚀 Getting Started

### 1️⃣ Clone the repository
```bash
git clone https://github.com/mn-iyze/threat-intelligence-dashboard.git
cd threat-intelligence-dashboard

2️⃣ Create virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

3️⃣ Install dependencies
pip install -r requirements.txt

4️⃣ Configure API key

Create a .env file in the project root:

VT_API_KEY=your_virustotal_api_key

5️⃣ Run the dashboard
streamlit run main.py