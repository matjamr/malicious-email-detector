import typing
import logging

from transformers import pipeline

from service.context import Context
from service.validator import Validator

logger = logging.getLogger(__name__)


class Email(Validator):
    def __init__(self):
        logger.info("Loading phishing email body detection model")
        self.pipeline = pipeline("text-classification", model="kamikaze20/phishing-email-detection_body")
        logger.info("Phishing email body detection model loaded")

    def validate(self, context: Context) -> None:
        """Analyze email body for phishing"""
        if not context.email_request.body:
            logger.debug("No email body to analyze")
            context.email_body_phishing_score = 0.0
            context.email_body_is_phishing = False
            return
        
        try:
            result = self.pipeline(context.email_request.body)
            logger.info(f"Email body phishing detection result: {result}")
            
            # Store results in context
            # Result format: [{"label": "LABEL", "score": 0.xx}]
            if isinstance(result, list) and len(result) > 0:
                first_result = result[0]
                context.email_body_phishing_score = float(first_result.get("score", 0.0))
                # Assuming label indicates phishing (adjust based on actual model labels)
                label = first_result.get("label", "").lower()
                context.email_body_is_phishing = "phishing" in label or "malicious" in label or context.email_body_phishing_score > 0.5
            else:
                context.email_body_phishing_score = 0.0
                context.email_body_is_phishing = False
        except Exception as e:
            logger.error(f"Error in email body phishing detection: {str(e)}", exc_info=True)
            context.email_body_phishing_score = 0.0
            context.email_body_is_phishing = False