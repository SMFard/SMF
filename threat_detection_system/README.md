# Threat Detection System

This is a lightweight, rule-based Threat Detection System built using the Flask framework in Python. It focuses on detecting phishing websites and intrusion attempts using predefined security rules and pattern-matching techniques.

## Features

- Web-based user interface for easy interaction.
- Phishing URL detection using regex-based pattern matching.
- Intrusion detection from uploaded log files analyzing failed login attempts and blacklisted IP access.
- SQLite database to store blacklisted URLs, suspicious IPs, and analysis reports.
- Alert system to notify users of detected threats (console alerts).
- Simple and beginner-friendly design, ideal for small-scale deployments.

## Getting Started

### Prerequisites

- Python 3.7 or higher
- pip package manager

### Installation

1. Clone or download this repository.
2. Navigate to the project directory:
   ```
   cd threat_detection_system
   ```
3. Install the required packages:
   ```
   pip install -r requirements.txt
   ```

### Running the Application

Run the Flask app:
```
python app.py
```

Open your browser and go to `http://127.0.0.1:5000` to access the web interface.

### Usage

- Enter a URL on the homepage to check if it is a phishing URL.
- Upload log files to analyze for intrusion attempts.
- View analysis results with threat severity and recommendations.

### Extending the System

- Add new phishing patterns in `detection.py`.
- Extend intrusion detection rules in `detection.py`.
- Integrate external APIs like VirusTotal or PhishTank for real-time detection.
- Enhance alerting mechanisms (email, SMS, etc.).

## Testing

- Use Postman or similar tools to test API endpoints:
  - `POST /api/check_url` with JSON body `{ "url": "http://example.com" }`
  - `POST /api/upload_log` with form-data file upload.

## License

This project is open source and free to use.
