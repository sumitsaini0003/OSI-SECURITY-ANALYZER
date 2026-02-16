# OSI Domain Spam Checker - Complete Security Analysis Platform

Advanced threat intelligence platform with comprehensive domain, URL, and email security analysis.

## 🚀 Features

### 1. **URL Reputation Scanning**
- Pattern-based detection (typosquatting, homographs)
- Spam database matching (500+ known threats)
- Legitimate domain whitelist (100+ domains)

### 2. **Domain Intelligence Gathering**
- Comprehensive DNS analysis (A, MX, TXT, NS, SOA, CNAME, AAAA)
- SSL certificate deep inspection
- Email security features (SPF, DMARC, DKIM)
- Security scoring (0-100)
- Trust level assessment

### 3. **Email Header Analysis**
- SPF/DKIM/DMARC validation
- Sender mismatch detection
- Phishing pattern recognition
- Email routing path analysis
- Risk scoring for email threats

### 4. **Redirect Chain Mapping**
- Track all HTTP redirects (301, 302, 307, 308)
- Detect HTTPS downgrades
- Identify multiple domain changes
- Map complete redirect path

### 5. **Webpage Source Inspection**
- Form and password field detection
- Suspicious keyword analysis
- JavaScript pattern checking
- Iframe counting
- External link analysis

### 6. **Unified Threat Scoring**
- Multi-factor weighted scoring:
  - Pattern Detection: 30%
  - URL Analysis: 25%
  - Domain Intelligence: 20%
  - Reputation: 15%
  - Domain Age: 10%
- Score breakdown by category
- Confidence level calculation
- Human-readable assessment summary

---

## 📦 Installation

### Option 1: Using Virtual Environment (Recommended)

```bash
# Navigate to project directory
cd "/Users/ashmtoshaeaed/Downloads/osinet code"

# Create virtual environment
python3 -m venv venv

# Activate virtual environment
# On macOS/Linux:
source venv/bin/activate

# On Windows:
# venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Start the server
python3 app.py
```

### Option 2: Global Installation

```bash
cd "/Users/ashmtoshaeaed/Downloads/osinet code"

# Install dependencies globally
pip3 install -r requirements.txt

# Start the server
python3 app.py
```

**Note**: When using virtual environment, remember to activate it each time:
```bash
source venv/bin/activate  # macOS/Linux
```

Server will run at: **http://localhost:5001**

---

## 🔌 API Endpoints

### 1. Main Domain Analysis
```bash
POST /api/analyze
```

**Request**:
```json
{
  "url": "example.com",
  "date": "2025-11-29",
  "include_intelligence": true,    // Optional: DNS/SSL analysis
  "include_url_analysis": true      // Optional: Redirect/webpage inspection
}
```

**Response**:
```json
{
  "domain": "example.com",
  "is_spam": false,
  "unified_score": {
    "total_score": 25.5,
    "threat_level": "low",
    "confidence": "high",
    "score_breakdown": {
      "pattern_detection": 10,
      "url_analysis": 15,
      "domain_intelligence": 30,
      "reputation": 0,
      "domain_age": 10
    },
    "contributing_factors": [...],
    "assessment_summary": "LOW RISK assessment with high confidence..."
  },
  "url_analysis": {
    "redirect_chain": [...],
    "total_redirects": 2,
    "webpage_analysis": {...}
  },
  "intelligence": {
    "dns_records": {...},
    "ssl_certificate": {...},
    "security_features": {...}
  }
}
```

### 2. Email Header Analysis
```bash
POST /api/analyze/email
```

**Request**:
```json
{
  "headers": "From: sender@domain.com\nAuthentication-Results: spf=pass..."
}
```

**Response**:
```json
{
  "from_domain": "domain.com",
  "authentication": {
    "spf": "pass",
    "dkim": "pass",
    "dmarc": "pass"
  },
  "risk_score": 15,
  "threat_level": "low",
  "warnings": [],
  "flags": []
}
```

### 3. Domain Intelligence
```bash
GET /api/intelligence/<domain>
```

Returns comprehensive DNS, SSL, and security feature analysis.

---

## 🎨 Web Interface

Access the modern web UI at **http://localhost:5001**

**Features**:
- Domain analysis form
- Risk score meter (animated 0-100)
- Color-coded threat levels
- Detection flags display
- Security warnings list
- Dataset statistics
- Beautiful glassmorphism UI

---

## 📊 Detection Capabilities

| Feature | Type | Risk Impact |
|---------|------|-------------|
| Typosquatting | Pattern | +70 points |
| Homograph Attack | Pattern | +80 points |
| Suspicious TLD | Pattern | +30 points |
| Known Spam DB | Reputation | +90 points |
| SPF Failure | Email | +50 points |
| DKIM Failure | Email | +45 points |
| DMARC Failure | Email | +40 points |
| Excessive Redirects | URL | +40 points |
| Password Fields | Webpage | +25 points |
| HTTPS Downgrade | Redirect | +30 points |
| Domain < 30 days | Age | +80 points |

---

## 💡 Usage Examples

### Analyze with Full Features
```bash
curl -X POST http://localhost:5001/api/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "url": "google.com",
    "include_intelligence": true,
    "include_url_analysis": true
  }' | jq
```

### Check Email Headers
```bash
curl -X POST http://localhost:5001/api/analyze/email \
  -H "Content-Type: application/json" \
  -d '{
    "headers": "From: John Doe <sender@example.com>\nAuthentication-Results: spf=pass dkim=pass dmarc=pass"
  }' | jq
```

### Get Domain Intelligence
```bash
curl http://localhost:5001/api/intelligence/google.com | jq
```

---

## 🗂️ Project Structure

```
osinet code/
├── app.py                      # Flask API server
├── detection_engine.py         # Pattern detection module
├── email_analyzer.py           # Email security analysis
├── intelligence_gatherer.py    # DNS/SSL intelligence
├── url_analyzer.py             # Redirect/webpage inspection
├── unified_scorer.py           # Multi-factor threat scoring
├── datasets/
│   ├── spam_domains.txt        # 500+ spam domains
│   ├── legitimate_domains.txt  # 100+ legitimate domains
│   └── suspicious_patterns.json # Detection patterns
├── templates/
│   └── index.html              # Web UI
├── static/
│   ├── css/styles.css          # UI styling
│   └── js/script.js            # Frontend logic
└── requirements.txt            # Python dependencies
```

---

## 📋 Dependencies

- Flask 3.0.0 - Web framework
- Flask-CORS 4.0.0 - Cross-origin support
- requests 2.31.0 - HTTP client
- python-whois 0.8.0 - WHOIS lookup
- dnspython 2.4.2 - DNS resolution
- pyOpenSSL 23.3.0 - SSL inspection
- beautifulsoup4 4.12.2 - HTML parsing

---

## 🎯 Threat Score Breakdown

**Unified scoring combines**:
1. **Pattern Detection (30%)**: Typosquatting, homographs, suspicious patterns
2. **URL Analysis (25%)**: Redirects, webpage content, forms
3. **Domain Intelligence (20%)**: DNS health, SSL validity, email security
4. **Reputation (15%)**: Spam database, legitimate whitelist
5. **Domain Age (10%)**: Registration date analysis

**Threat Levels**:
- 0-34: **LOW** - Domain appears safe
- 35-59: **MEDIUM** - Verify before proceeding
- 60-79: **HIGH** - Exercise extreme caution
- 80-100: **CRITICAL** - Immediate threat detected

---

## 🔒 Security Features

✅ **500+ Spam Domain Database**  
✅ **Typosquatting Detection** (character substitution, omission, insertion)  
✅ **Homograph Attack Detection** (Unicode lookalikes)  
✅ **Email Authentication** (SPF/DKIM/DMARC)  
✅ **Redirect Chain Mapping** (up to 10 hops)  
✅ **Webpage Content Inspection** (forms, keywords, scripts)  
✅ **DNS Intelligence** (7+ record types)  
✅ **SSL Certificate Analysis** (validity, expiration, SANs)  
✅ **Unified Threat Scoring** (multi-factor weighted)  
✅ **Confidence Assessment** (high/medium/low)  

---

## 📝 API Response Fields

### Unified Score Object
```json
{
  "total_score": 25.5,           // 0-100 combined risk score
  "threat_level": "low",         // low/medium/high/critical
  "confidence": "high",          // assessment confidence
  "score_breakdown": {           // individual category scores
    "pattern_detection": 10,
    "url_analysis": 15,
    "domain_intelligence": 30,
    "reputation": 0,
    "domain_age": 10
  },
  "weights": {                   // category weights (sum to 100)
    "pattern_detection": 30,
    "url_analysis": 25,
    "domain_intelligence": 20,
    "reputation": 15,
    "domain_age": 10
  },
  "contributing_factors": [      // top risk contributors
    "URL: Excessive redirects (8 hops)",
    "Pattern: TYPOSQUATTING"
  ],
  "assessment_summary": "..."    // human-readable summary
}
```

---

## 🚦 Status

- ✅ Backend modules implemented
- ✅ Flask API endpoints active
- ✅ Unified threat scoring operational
- ✅ All detection features functional
- ⚠️ Frontend UI awaiting enhancement for new features

**Server Status**: Running at http://localhost:5001

---

## 📚 Documentation

- [Implementation Plan](advanced_features_plan.md)
- [Walkthrough](walkthrough.md)
- [Task Tracking](task.md)

---

## 🙏 Credits

OSI Domain Spam Checker - Advanced Security Analysis Platform  
© 2025 - Comprehensive Threat Intelligence System

---

**Need help?** Check the API documentation or review the walkthrough for detailed usage examples.
