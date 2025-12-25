import typing
import logging
import re

from transformers import pipeline

from service.context import Context
from service.validator import Validator

logger = logging.getLogger(__name__)


class MaliciousUrlDetector(Validator):
    def __init__(self):
        logger.info("Loading malicious URL detection model")
        self.pipeline = pipeline("text-classification", model="kmack/malicious-url-detection")
        logger.info("Malicious URL detection model loaded")
        # URL regex pattern
        self.url_pattern = re.compile(
            r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        )

    def validate(self, context: Context) -> None:
        """Analyze URLs in email body for malicious content"""
        if not context.email_request.body:
            logger.debug("No email body to analyze for URLs")
            context.url_detection_results = []
            context.malicious_url_count = 0
            return
        
        try:
            # Extract URLs from body
            urls = self.url_pattern.findall(context.email_request.body)
            logger.info(f"Found {len(urls)} URL(s) in email body")
            
            context.url_detection_results = []
            context.malicious_url_count = 0
            
            for url in urls:
                try:
                    result = self.pipeline(url)
                    logger.info(f"URL '{url}' detection result: {result}")
                    
                    if isinstance(result, list) and len(result) > 0:
                        first_result = result[0]
                        score = float(first_result.get("score", 0.0))
                        label = first_result.get("label", "").lower()
                        is_malicious = "malicious" in label or "phishing" in label or score > 0.5
                        
                        context.url_detection_results.append({
                            "url": url,
                            "is_malicious": is_malicious,
                            "score": score,
                            "label": label
                        })
                        
                        if is_malicious:
                            context.malicious_url_count += 1
                except Exception as e:
                    logger.error(f"Error analyzing URL '{url}': {str(e)}", exc_info=True)
                    context.url_detection_results.append({
                        "url": url,
                        "is_malicious": False,
                        "score": 0.0,
                        "error": str(e)
                    })
        except Exception as e:
            logger.error(f"Error in URL detection: {str(e)}", exc_info=True)
            context.url_detection_results = []
            context.malicious_url_count = 0