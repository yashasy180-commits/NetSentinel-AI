# Architecture

Frontend (React/Vite)
        |
        v
Flask REST API + WebSocket
        |
  +-----+--------------------+
  |                          |
Database                 Detection Engine
  |                          |
SQLite              Feature Extraction -> ML Model
  |                          |
  +------------ Alerts ------+
