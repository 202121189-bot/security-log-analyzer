# 🚨 Security Log Analyzer

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![Domain](https://img.shields.io/badge/Domain-DFIR-red.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)

A DFIR tool that parses and analyzes Linux authentication logs (`/var/log/auth.log`) to detect brute-force attacks, suspicious IPs, and malicious activity.

## ✨ Features

- 🔍 **Log Parser** — parses SSH auth events (accepted, failed, invalid user, sudo)
- 💥 **Brute-Force Detector** — flags IPs with repeated failed attempts in a time window
- 🕵️ **Suspicious IP Detector** — scores IPs by failures, enumeration, invalid users
- 👤 **User Activity** — identifies top targeted accounts
- 🌐 **IP Analysis** — ranks source IPs by activity
- 📋 **Timeline** — chronological event reconstruction
- 📊 **Multi-format Report** — HTML, JSON, CSV
- 🎯 **Severity Levels** — CRITICAL / HIGH / MEDIUM

## 🛠️ Requirements

- Python 3.8+
- `jinja2`

Install:

```bash
pip install -r requirements.txt