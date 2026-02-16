# OSI Domain Spam Checker - Web Interface

A beautiful, modern web interface for analyzing domains for spam and phishing activity.

## Features

- 🛡️ **Comprehensive Domain Analysis**: HTTP status, DNS, SSL, and WHOIS information
- 🔍 **Spam Detection**: Check domains against a persistent dataset
- 📊 **Dataset Management**: Mark domains as spam or clean through the web UI
- 🎨 **Modern Design**: Dark theme with glassmorphism effects and smooth animations
- 📱 **Responsive**: Works on desktop, tablet, and mobile devices

## Setup Instructions

### 1. Install Dependencies

```bash
cd "/Users/ashmtoshaeaed/Downloads/osinet code"
pip3 install -r requirements.txt
```

### 2. Run the Server

```bash
python3 app.py
```

### 3. Access the Application

Open your browser and navigate to:
```
http://localhost:5000
```

## Usage

1. **Analyze a Domain**:
   - Enter a URL or domain name (e.g., `example.com` or `https://example.com`)
   - Optionally select a date to check (defaults to today)
   - Click "Analyze Domain"

2. **View Results**:
   - See comprehensive analysis including reachability, IP address, SSL certificate, and WHOIS data
   - Check if the domain is flagged as spam in the dataset
   - Review security warnings and heuristics

3. **Mark Domains**:
   - Use "Mark as Spam" or "Mark as Clean" to update the dataset
   - Dataset is automatically saved to `~/Downloads/domains.txt`

## API Endpoints

- `GET /` - Main web interface
- `POST /api/analyze` - Analyze a domain
  - Body: `{"url": "example.com", "date": "2025-11-28"}`
- `POST /api/mark_spam` - Mark domain as spam/clean
  - Body: `{"domain": "example.com", "is_spam": true, "date": "2025-11-28"}`
- `GET /api/dataset/stats` - Get dataset statistics

## Technical Stack

- **Backend**: Flask (Python)
- **Frontend**: HTML5, CSS3, JavaScript (ES6+)
- **Styling**: Custom CSS with glassmorphism and animations
- **Fonts**: Google Fonts (Inter)

## File Structure

```
osinet code/
├── app.py                  # Flask application
├── osi1.py                 # Original CLI tool
├── requirements.txt        # Python dependencies
├── templates/
│   └── index.html         # Web interface HTML
└── static/
    ├── css/
    │   └── styles.css     # Modern styling
    └── js/
        └── script.js      # Interactive functionality
```

## Notes

- Dataset is stored at `~/Downloads/domains.txt`
- Server runs on port 5000 by default
- Debug mode is enabled for development

## Original CLI Tool

The original command-line tool (`osi1.py`) is still available and can be run with:
```bash
python3 osi1.py
```
