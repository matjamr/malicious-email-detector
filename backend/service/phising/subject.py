import typing
import logging

from transformers import pipeline

from service.context import Context
from service.validator import Validator

logger = logging.getLogger(__name__)


class Subject(Validator):
    def __init__(self):
        logger.info("Loading phishing subject detection model")
        self.pipeline = pipeline("text-classification", model="kamikaze20/phishing-email-detection_subject")
        logger.info("Phishing subject detection model loaded")

    def validate(self, context: Context) -> None:
        """Analyze subject for phishing"""
        if not context.email_request.subject:
            logger.debug("No subject to analyze")
            context.subject_phishing_score = 0.0
            context.subject_is_phishing = False
            return
        
        try:
            result = self.pipeline(context.email_request.subject)
            logger.info(f"Subject phishing detection result: {result}")
            
            # Store results in context
            if isinstance(result, list) and len(result) > 0:
                first_result = result[0]
                context.subject_phishing_score = float(first_result.get("score", 0.0))
                label = first_result.get("label", "").lower()
                context.subject_is_phishing = "phishing" in label or "malicious" in label or context.subject_phishing_score > 0.5
            else:
                context.subject_phishing_score = 0.0
                context.subject_is_phishing = False
        except Exception as e:
            logger.error(f"Error in subject phishing detection: {str(e)}", exc_info=True)
            context.subject_phishing_score = 0.0
            context.subject_is_phishing = False