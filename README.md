![C++](https://img.shields.io/badge/C%2B%2B-00599C?style=for-the-badge&logo=c%2B%2B&logoColor=white)![Arduino IDE](https://img.shields.io/badge/Arduino%20IDE-00979D?style=for-the-badge&logo=arduino&logoColor=white)![ESP32-S3](https://img.shields.io/badge/ESP32--S3-E7352C?style=for-the-badge&logo=espressif&logoColor=white)

🐉 EJDER S3 AI v3.0 - Advanced WiFi Pentest Suite
EJDER S3 AI is a professional-grade wireless security auditing tool engineered for the ESP32-S3 architecture. Leveraging dual-core processing and an integrated AI scoring heuristic, v3.0 focuses on stability, resource management, and intelligent target acquisition.

💎 Core Architecture
Asynchronous Dual-Core Execution: * Core 0: Dedicated to the Web Server and UI management, ensuring a lag-free control panel.

Core 1: Handles high-speed 802.11 frame injection and real-time signal processing.

AI-Driven Target Analysis: Uses a multi-factor heuristic (RSSI, Channel Congestion, and SSID Vendor Profiling) to calculate a "Vulnerability Score" for each detected network.

Thread-Safe Operations: Implements FreeRTOS Semaphores for secure data sharing between cores during network scans and attack execution.

⚡ Attack Vectors
AI-Enhanced Deauthentication: Targeted frame injection to audit client-to-AP connectivity.

Lethal Burst Mode: High-velocity packet flooding across the 2.4GHz spectrum.

Multi-SSID Beacon Flood: Generates up to 20+ virtual Access Points with randomized MAC addresses and unique SSIDs to test device saturation.

Probe Request Exhaustion: Floods the environment with probe requests to analyze how nearby devices respond to known/hidden networks.

🛠️ Deployment
Hardware: ESP32-S3 Development Board.

Environment: Arduino IDE or PlatformIO.

Dependencies: esp_wifi.h, FreeRTOS, WebServer.

Configuration: * Flash the firmware.

Connect to the "EJDER" SSID (Default Pass: EJDERYAV3S3).

Navigate to 192.168.4.1 to access the AI dashboard.

📜 Roadmap
[x] v3.0: Stable AI Base & Dual-Core Implementation.

[ ] v3.1: Aggressive Edition (Custom Reason Codes, Null Frame Attacks, and Enhanced Channel Hopping).

⚖️ Disclaimer
This software is intended for educational purposes and authorized security auditing only. Unauthorized access to or disruption of wireless networks is illegal. The developer (SirAtilotty) assumes no liability for misuse of this tool.

Developed by: SirAtilotty 🐉

