import typing
import logging
import re
import math

from transformers import pipeline

from service.context import Context
from service.validator import Validator

logger = logging.getLogger(__name__)


class MaliciousUrlDetector(Validator):
    def __init__(self):
        logger.info("Loading malicious URL detection model")
        self.pipeline = pipeline("text-classification", model="kmack/malicious-url-detection")
        # Get the tokenizer to check max length
        self.max_length = 512  # Default max length for most transformer models
        try:
            if hasattr(self.pipeline, 'tokenizer') and self.pipeline.tokenizer:
                self.max_length = getattr(self.pipeline.tokenizer, 'model_max_length', 512)
                if self.max_length > 100000:  # Some tokenizers return a very large default
                    self.max_length = 512
        except Exception as e:
            logger.warning(f"Could not determine model max length, using default 512: {e}")
        logger.info(f"Malicious URL detection model loaded (max_length={self.max_length})")
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
                    # Truncate URL if it's too long (unlikely but safe)
                    truncated_url = url[:self.max_length * 3] if len(url) > self.max_length * 3 else url
                    result = self.pipeline(truncated_url, truncation=True, max_length=self.max_length)
                    logger.info(f"URL '{url}' detection result: {result}")
                    
                    if isinstance(result, list) and len(result) > 0:
                        first_result = result[0]
                        raw_score = float(first_result.get("score", 0.0))
                        # Sanitize score to prevent inf/nan values
                        score = 0.0 if (math.isnan(raw_score) or math.isinf(raw_score)) else max(0.0, min(1.0, raw_score))
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