from flask import Flask, render_template, request, jsonify
from werkzeug.utils import secure_filename
import os
import re
import sqlite3
from detection import is_phishing_url, analyze_log_file, alert_user, is_valid_email, is_valid_website, is_threat_email
from database import init_db, add_blacklist_url, add_suspicious_ip, save_analysis_report, get_blacklist_urls, get_suspicious_ips

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB max upload size

if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

# Initialize database
init_db()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/check_url', methods=['POST'])
def check_url():
    data = request.get_json()
    url = data.get('url', '')
    if not url:
        return jsonify({'error': 'No URL provided'}), 400

    # Validate URL format
    if not is_valid_website(url):
        return jsonify({'error': 'Invalid URL format. Please enter a valid URL.'}), 400

    # Check if URL is in blacklist
    blacklist = get_blacklist_urls()
    if url in blacklist:
        return jsonify({
            'threat_detected': True,
            'threat_type': 'Blacklisted URL',
            'severity': 'High',
            'recommendation': 'Do not visit this URL.'
        })

    # Use detection logic
    phishing_detected = is_phishing_url(url)
    if phishing_detected:
        add_blacklist_url(url)
        save_analysis_report(url, 'URL', 'Phishing URL detected', 'High')
        alert_user(f"Phishing URL detected: {url}")
        return jsonify({
            'threat_detected': True,
            'threat_type': 'Phishing URL',
            'severity': 'High',
            'recommendation': 'Avoid this URL and report it.'
        })
    else:
        save_analysis_report(url, 'URL', 'No threat detected', 'Low')
        return jsonify({
            'threat_detected': False,
            'message': 'URL appears safe.'
        })

@app.route('/api/check_email', methods=['POST'])
def check_email():
    data = request.get_json()
    email = data.get('email', '')
    if not email:
        return jsonify({'error': 'No email provided'}), 400

    valid = is_valid_email(email)
    if valid:
        is_threat, suggestion = is_threat_email(email)
        if is_threat:
            save_analysis_report(email, 'Email', f'Threat email detected. Suggestion: {suggestion}', 'High')
            alert_user(f"Threat email detected: {email}, suggestion: {suggestion}")
            return jsonify({
                'valid': True,
                'threat': True,
                'message': f'Email format is valid. Threat detected. Did you mean {suggestion}?',
                'suggestion': suggestion
            })
        else:
            save_analysis_report(email, 'Email', 'Valid email format', 'Low')
            return jsonify({
                'valid': True,
                'threat': False,
                'message': 'Email format is valid. No threat detected.'
            })
    else:
        save_analysis_report(email, 'Email', 'Invalid email format', 'Medium')
        alert_user(f"Invalid email format detected: {email}")
        return jsonify({
            'valid': False,
            'threat': False,
            'message': 'Invalid email format.'
        })

@app.route('/api/check_website', methods=['POST'])
def check_website():
    data = request.get_json()
    website = data.get('website', '')
    if not website:
        return jsonify({'error': 'No website URL provided'}), 400

    valid = is_valid_website(website)
    if valid:
        save_analysis_report(website, 'Website', 'Valid website URL format', 'Low')
        return jsonify({
            'valid': True,
            'message': 'Website URL format is valid.'
        })
    else:
        save_analysis_report(website, 'Website', 'Invalid website URL format', 'Medium')
        alert_user(f"Invalid website URL format detected: {website}")
        return jsonify({
            'valid': False,
            'message': 'Invalid website URL format.'
        })

@app.route('/api/upload_log', methods=['POST'])
def upload_log():
    if 'logfile' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    file = request.files['logfile']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400
    filename = secure_filename(file.filename)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(filepath)

    # Analyze log file
    analysis_results = analyze_log_file(filepath)
    for ip, reason, severity in analysis_results.get('alerts', []):
        add_suspicious_ip(ip)
        save_analysis_report(ip, 'IP', reason, severity)
        alert_user(f"Suspicious activity detected from IP: {ip} - {reason}")

    return jsonify({
        'analysis': analysis_results,
        'message': 'Log file analyzed.'
    })

if __name__ == '__main__':
    app.run(debug=True)
