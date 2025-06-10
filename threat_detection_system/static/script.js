document.addEventListener('DOMContentLoaded', () => {
    const urlForm = document.getElementById('urlForm');
    const urlInput = document.getElementById('urlInput');
    const urlResult = document.getElementById('urlResult');

    const emailForm = document.getElementById('emailForm');
    const emailInput = document.getElementById('emailInput');
    const emailResult = document.getElementById('emailResult');

    const logForm = document.getElementById('logForm');
    const logFileInput = document.getElementById('logFileInput');
    const logResult = document.getElementById('logResult');

    urlForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        urlResult.textContent = '';
        urlResult.className = 'result';

        const url = urlInput.value.trim();
        if (!url) {
            urlResult.textContent = 'Please enter a URL.';
            urlResult.classList.add('error');
            return;
        }

        try {
            const response = await fetch('/api/check_url', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url })
            });
            const data = await response.json();
            if (response.ok) {
                if (data.threat_detected) {
                    urlResult.textContent = `Threat Detected: ${data.threat_type}. Severity: ${data.severity}. Recommendation: ${data.recommendation}`;
                    urlResult.classList.add('warning');
                } else {
                    urlResult.textContent = data.message || 'No threat detected.';
                    urlResult.classList.add('success');
                }
            } else {
                urlResult.textContent = data.error || 'Error checking URL.';
                urlResult.classList.add('error');
            }
        } catch (err) {
            urlResult.textContent = 'Error connecting to server.';
            urlResult.classList.add('error');
        }
    });

    emailForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        emailResult.textContent = '';
        emailResult.className = 'result';

        const email = emailInput.value.trim();
        if (!email) {
            emailResult.textContent = 'Please enter an email.';
            emailResult.classList.add('error');
            return;
        }

        try {
            const response = await fetch('/api/check_email', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email })
            });
            const data = await response.json();
            if (response.ok) {
                if (data.valid) {
                    emailResult.textContent = data.message || 'Email format is valid.';
                    emailResult.classList.add('success');
                } else {
                    emailResult.textContent = data.message || 'Invalid email format.';
                    emailResult.classList.add('error');
                }
            } else {
                emailResult.textContent = data.error || 'Error checking email.';
                emailResult.classList.add('error');
            }
        } catch (err) {
            emailResult.textContent = 'Error connecting to server.';
            emailResult.classList.add('error');
        }
    });

    logForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        logResult.textContent = '';
        logResult.className = 'result';

        const file = logFileInput.files[0];
        if (!file) {
            logResult.textContent = 'Please select a log file.';
            logResult.classList.add('error');
            return;
        }

        const formData = new FormData();
        formData.append('logfile', file);

        try {
            const response = await fetch('/api/upload_log', {
                method: 'POST',
                body: formData
            });
            const data = await response.json();
            if (response.ok) {
                const alerts = data.analysis.alerts;
                if (alerts.length > 0) {
                    let alertMessages = alerts.map(a => `IP: ${a[0]}, Reason: ${a[1]}, Severity: ${a[2]}`).join('\\n');
                    logResult.textContent = `Alerts:\\n${alertMessages}`;
                    logResult.classList.add('warning');
                } else {
                    logResult.textContent = 'No suspicious activity detected in log file.';
                    logResult.classList.add('success');
                }
            } else {
                logResult.textContent = data.error || 'Error analyzing log file.';
                logResult.classList.add('error');
            }
        } catch (err) {
            logResult.textContent = 'Error connecting to server.';
            logResult.classList.add('error');
        }
    });
});
