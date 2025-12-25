# Email Spam Detection API

A Flask REST API for analyzing email metadata, content, and attachments to detect potential spam or security threats.

## Features

- **Comprehensive Email Analysis**: Analyzes subject, body, sender, recipients, attachments, and metadata
- **Security Detection**: Identifies suspicious patterns, URLs, and risky attachments
- **Risk Scoring**: Provides a 0-100 risk score for each email
- **Logging**: Detailed console logging for all operations
- **Batch Processing**: Analyze multiple emails at once

## Installation

1. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

1. Start the Flask server:
```bash
python app.py
```

The server will start on `http://localhost:5000`

## API Endpoints

### POST /analyze

Analyze a single email.

**Request Body:**
```json
{
  "subject": "Important: Act Now!",
  "body": "Click here to claim your prize!",
  "from": "sender@example.com",
  "to": "recipient@example.com",
  "cc": ["cc1@example.com"],
  "bcc": ["bcc@example.com"],
  "reply_to": "noreply@example.com",
  "date": "2024-01-01T12:00:00",
  "attachments": [
    {
      "filename": "document.pdf",
      "size": 1024,
      "content_type": "application/pdf"
    }
  ],
  "headers": {
    "Message-ID": "<123456@example.com>",
    "X-Mailer": "SomeMailer"
  }
}
```

**Response:**
```json
{
  "timestamp": "2024-01-01T12:00:00",
  "metadata": {...},
  "content_analysis": {...},
  "sender_analysis": {...},
  "recipient_analysis": {...},
  "attachment_analysis": {...},
  "security_analysis": {...},
  "overall_score": 45
}
```

### POST /analyze/batch

Analyze multiple emails in a single request.

**Request Body:**
```json
{
  "emails": [
    { ... email data ... },
    { ... email data ... }
  ]
}
```

### GET /health

Health check endpoint.

## Analysis Features

The `EmailAnalyzer` class performs the following analyses:

1. **Metadata Analysis**: Date validation, header analysis
2. **Content Analysis**: Subject and body length, suspicious keywords, URL detection, HTML/image detection
3. **Sender Analysis**: Email validation, domain extraction, display name detection
4. **Recipient Analysis**: Count analysis, domain extraction for to/cc/bcc
5. **Attachment Analysis**: File type detection, size calculation, executable/script detection
6. **Security Analysis**: Risk level assessment, suspicious indicators, security flags

## Logging

All operations are logged to the console with timestamps. The logs include:
- Request received notifications
- Analysis progress
- Results and risk scores
- Error messages with stack traces

## Example Usage

```bash
# Using curl
curl -X POST http://localhost:5000/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "subject": "Urgent: Claim your prize!",
    "body": "Click here now!",
    "from": "noreply@example.com",
    "to": "user@example.com"
  }'
```


