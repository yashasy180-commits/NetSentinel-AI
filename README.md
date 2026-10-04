# NetSentinel AI

Professional AI/ML-powered Network Intrusion Detection & Security Monitoring System.

## 8 Core Modules
1. Authentication & User Management
2. Network Traffic Collection
3. Feature Extraction & Preprocessing
4. AI/ML Intrusion Detection Engine
5. Real-Time Threat Monitoring
6. Threat Detection & Alert Management
7. Security Analytics & Reporting
8. Admin Control & System Management

## Structure
- `backend/` Flask API, network engine, ML engine, database
- `frontend/` React/Vite dashboard
- `tests/` backend tests
- `docs/` architecture/setup/API notes

## Windows quick start
### Backend
```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python app.py
```

### Frontend
Open another PowerShell terminal:
```powershell
cd frontend
npm install
npm run dev
```

Backend: http://127.0.0.1:5000
Frontend: http://localhost:5173

This repository is a professional project scaffold. Add a properly sourced intrusion-detection dataset and train the ML model before claiming detection performance.
