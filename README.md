# 🛡️ Cyber Threat Intelligence (CTI) Platform

A student-built Cyber Threat Intelligence (CTI) platform designed to collect, analyze, and visualize security threat data.
This project integrates Python (backend) and React + TypeScript (frontend) with modular components for scanning, monitoring, and reporting cyber threats.

# 📂 Project Structure
project/
│── app.py                  # Flask/FastAPI entry point
│── requirements.txt         # Python dependencies
│── package.json             # Frontend dependencies
│── vite.config.ts           # Vite configuration for React
│── tailwind.config.js       # Tailwind CSS configuration
│── static/                  # CSS & JS assets
│── templates/               # HTML templates (Jinja2)
│── modules/                 # Core CTI modules
│   ├── file_scanner.py
│   ├── url_scanner.py
│   ├── usb_monitor.py
│   ├── threat_database.py
│   └── report_generator.py
│── src/                     # React frontend
│   ├── main.tsx
│   ├── App.tsx
│   └── components/
│       └── Dashboard.tsx


# ⚡ Features

File Scanner – Detect malicious or suspicious files

URL Scanner – Check websites for threats

USB Monitor – Monitor removable devices for malware

Threat Database – Centralized storage of known threats

Report Generator – Create structured security reports

Web Dashboard – React + Tailwind UI for visualization

# 🚀 Getting Started

1️⃣ Backend Setup (Python)

cd project
python3 -m venv venv
source venv/bin/activate   # On Windows: venv\Scripts\activate
pip install -r requirements.txt
python app.py

This starts the backend server (Flask/FastAPI).

2️⃣ Frontend Setup (React + Vite)

cd project
npm install
npm run dev

# 🛠️ Tech Stack

Backend: Python, Flask/FastAPI

Frontend: React, TypeScript, Vite, Tailwind CSS

Database: (Optional) SQLite / PostgreSQL for storing threat data

Reports: Auto-generated PDF/HTML reports

# 📊 Dashboard Preview

Threat statistics and trends

Recent file/URL scan results

USB monitoring logs

Report download option

# 🤝 Contributing

Contributions are welcome! Fork this repo and submit a pull request.

# 📜 License

This project is licensed under the MIT License.
