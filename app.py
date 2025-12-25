from flask import Flask, request, jsonify
from flask_cors import CORS
import logging
from datetime import datetime
from models.models import (
    EmailRequest,
    BatchEmailRequest,
    EmailAnalysisResponse,
    HealthCheckResponse,
    ErrorResponse,
    BatchAnalysisResponse
)
from service.context import Context
from service.phising.email import Email
from service.phising.sender import Sender
from service.phising.subject import Subject
from service.url.MaliciousUrlDetector import MaliciousUrlDetector
from service.validator import Validator

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
    ]
)

logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)


flow: list[Validator] = [
    Email(),
    Sender(),
    Subject(),
    MaliciousUrlDetector()
]

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    logger.info("Health check requested")
    response = HealthCheckResponse(status="healthy", service="email-analyzer")
    return jsonify(response.to_dict()), 200


@app.route('/analyze', methods=['POST'])
def analyze_email():
    """
    Analyze email endpoint
    
    Expected JSON payload (EmailRequest):
    {
        "subject": "Email subject",
        "body": "Email body content",
        "from": "sender@example.com",
        "to": "recipient@example.com",
        "cc": ["cc1@example.com", "cc2@example.com"],
        "bcc": ["bcc@example.com"],
        "reply_to": "reply@example.com",
        "date": "2024-01-01T12:00:00",
        "attachments": [
            {"filename": "file1.pdf", "size": 1024, "content_type": "application/pdf"},
            {"filename": "file2.jpg", "size": 2048, "content_type": "image/jpeg"}
        ],
        "headers": {
            "X-Mailer": "SomeMailer",
            "Message-ID": "<123456@example.com>"
        }
    }
    
    Returns: EmailAnalysisResponse
    """
    try:
        logger.info("=" * 60)
        logger.info(f"Received email analysis request at {datetime.now().isoformat()}")
        
        # Get JSON data from request
        data = request.get_json()
        
        if not data:
            logger.warning("No JSON data provided in request")
            error_response = ErrorResponse(error="No JSON data provided")
            return jsonify(error_response.to_dict()), 400
        
        # Parse request into typed model
        try:
            email_request = EmailRequest.from_dict(data)
            logger.info(f"Parsed EmailRequest with fields: subject={bool(email_request.subject)}, "
                       f"from={bool(email_request.from_)}, attachments={len(email_request.attachments)}")
        except Exception as parse_error:
            logger.warning(f"Failed to parse EmailRequest: {str(parse_error)}")
            error_response = ErrorResponse(error="Invalid request format", message=str(parse_error))
            return jsonify(error_response.to_dict()), 400

        context = Context(email_request)
        for validator in flow:
            validator.validate(context)

        # Convert to typed response model
        analysis_response = EmailAnalysisResponse.from_dict({})
        
        return jsonify(analysis_response.to_dict()), 200
        
    except Exception as e:
        logger.error(f"Error analyzing email: {str(e)}", exc_info=True)
        error_response = ErrorResponse(error="Internal server error", message=str(e))
        return jsonify(error_response.to_dict()), 500


@app.route('/analyze/batch', methods=['POST'])
def analyze_email_batch():
    """
    Analyze multiple emails in batch
    
    Expected JSON payload (BatchEmailRequest):
    {
        "emails": [
            { ... email data ... },
            { ... email data ... }
        ]
    }
    
    Returns: BatchAnalysisResponse
    """
    try:
        logger.info("=" * 60)
        logger.info(f"Received batch email analysis request at {datetime.now().isoformat()}")
        
        data = request.get_json()
        
        if not data or 'emails' not in data:
            logger.warning("Invalid batch request: missing 'emails' key")
            error_response = ErrorResponse(error="Missing 'emails' key in request")
            return jsonify(error_response.to_dict()), 400
        
        # Parse request into typed model
        try:
            batch_request = BatchEmailRequest.from_dict(data)
            logger.info(f"Parsed BatchEmailRequest with {len(batch_request.emails)} emails")
        except Exception as parse_error:
            logger.warning(f"Failed to parse BatchEmailRequest: {str(parse_error)}")
            error_response = ErrorResponse(error="Invalid request format", message=str(parse_error))
            return jsonify(error_response.to_dict()), 400
        
        # Process each email
        results = []
        for idx, email_request in enumerate(batch_request.emails):
            logger.info(f"Analyzing email {idx + 1}/{len(batch_request.emails)}")
            email_dict = email_request.to_dict()
            analysis_dict = email_analyzer.analyze(email_dict)
            analysis_response = EmailAnalysisResponse.from_dict(analysis_dict)
            results.append(analysis_response)
        
        logger.info(f"Batch analysis completed: {len(results)} emails processed")
        logger.info("=" * 60)
        
        batch_response = BatchAnalysisResponse(total=len(results), results=results)
        return jsonify(batch_response.to_dict()), 200
        
    except Exception as e:
        logger.error(f"Error in batch analysis: {str(e)}", exc_info=True)
        error_response = ErrorResponse(error="Internal server error", message=str(e))
        return jsonify(error_response.to_dict()), 500


if __name__ == '__main__':
    logger.info("Starting Email Analyzer Flask Application")
    logger.info("Server will be available at http://localhost:5000")
    app.run(debug=True, host='0.0.0.0', port=5000)

