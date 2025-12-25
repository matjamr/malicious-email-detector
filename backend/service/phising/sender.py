import typing
import logging

from transformers import pipeline

from service.context import Context
from service.validator import Validator

logger = logging.getLogger(__name__)


class Sender(Validator):
    def __init__(self):
        logger.info("Loading phishing sender detection model")
        self.pipeline = pipeline("text-classification", model="kamikaze20/phishing-email-detection_sender")
        logger.info("Phishing sender detection model loaded")

    def validate(self, context: Context) -> None:
        """Analyze sender for phishing"""
        if not context.email_request.from_:
            logger.debug("No sender to analyze")
            context.sender_phishing_score = 0.0
            context.sender_is_phishing = False
            return
        
        try:
            result = self.pipeline(context.email_request.from_)
            logger.info(f"Sender phishing detection result: {result}")
            
            # Store results in context
            if isinstance(result, list) and len(result) > 0:
                first_result = result[0]
                context.sender_phishing_score = float(first_result.get("score", 0.0))
                label = first_result.get("label", "").lower()
                context.sender_is_phishing = "phishing" in label or "malicious" in label or context.sender_phishing_score > 0.5
            else:
                context.sender_phishing_score = 0.0
                context.sender_is_phishing = False
        except Exception as e:
            logger.error(f"Error in sender phishing detection: {str(e)}", exc_info=True)
            context.sender_phishing_score = 0.0
            context.sender_is_phishing = False