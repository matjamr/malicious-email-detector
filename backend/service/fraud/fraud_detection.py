import typing
import logging

from transformers import pipeline

from service.context import Context
from service.validator import Validator

logger = logging.getLogger(__name__)


class FraudDetection(Validator):
    def __init__(self):
        logger.info("Loading fraud detection model")
        self.pipeline = pipeline("text-classification", model="tush9905/email_fraud_detector")
        logger.info("Fraud detection model loaded")

    def validate(self, context: Context) -> None:
        """Analyze email body for fraud"""
        if not context.email_request.body:
            logger.debug("No email body to analyze for fraud")
            context.fraud_score = 0.0
            context.is_fraud = False
            return
        
        try:
            result = self.pipeline(context.email_request.body)
            logger.info(f"Fraud detection result: {result}")
            
            # Store results in context
            if isinstance(result, list) and len(result) > 0:
                first_result = result[0]
                context.fraud_score = float(first_result.get("score", 0.0))
                label = first_result.get("label", "").lower()
                context.is_fraud = "fraud" in label or "malicious" in label or context.fraud_score > 0.5
            else:
                context.fraud_score = 0.0
                context.is_fraud = False
        except Exception as e:
            logger.error(f"Error in fraud detection: {str(e)}", exc_info=True)
            context.fraud_score = 0.0
            context.is_fraud = False