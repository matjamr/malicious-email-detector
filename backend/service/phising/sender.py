import typing
import logging
import math

from transformers import pipeline

from service.context import Context
from service.validator import Validator

logger = logging.getLogger(__name__)


class Sender(Validator):
    def __init__(self):
        logger.info("Loading phishing sender detection model")
        self.pipeline = pipeline("text-classification", model="kamikaze20/phishing-email-detection_sender")
        # Get the tokenizer to check max length
        self.max_length = 512  # Default max length for most transformer models
        try:
            if hasattr(self.pipeline, 'tokenizer') and self.pipeline.tokenizer:
                self.max_length = getattr(self.pipeline.tokenizer, 'model_max_length', 512)
                if self.max_length > 100000:  # Some tokenizers return a very large default
                    self.max_length = 512
        except Exception as e:
            logger.warning(f"Could not determine model max length, using default 512: {e}")
        logger.info(f"Phishing sender detection model loaded (max_length={self.max_length})")
    
    def _truncate_text(self, text: str, max_tokens: int = None) -> str:
        """Truncate text to fit within token limit"""
        if max_tokens is None:
            max_tokens = self.max_length
        
        # Simple character-based truncation (rough approximation: 3 chars per token)
        max_chars = max_tokens * 3  # 3 chars per token on average
        
        if len(text) <= max_chars:
            return text
        
        # Truncate and add ellipsis
        truncated = text[:max_chars].rsplit(' ', 1)[0]  # Cut at word boundary
        logger.debug(f"Truncated sender from {len(text)} to {len(truncated)} characters")
        return truncated

    def validate(self, context: Context) -> None:
        """Analyze sender for phishing"""
        if not context.email_request.from_:
            logger.debug("No sender to analyze")
            context.sender_phishing_score = 0.0
            context.sender_is_phishing = False
            return
        
        try:
            # Truncate sender if it's too long for the model (unlikely but safe)
            sender_text = context.email_request.from_
            truncated_sender = self._truncate_text(sender_text, self.max_length)
            
            result = self.pipeline(truncated_sender, truncation=True, max_length=self.max_length)
            logger.info(f"Sender phishing detection result: {result}")
            
            # Store results in context
            if isinstance(result, list) and len(result) > 0:
                first_result = result[0]
                raw_score = float(first_result.get("score", 0.0))
                # Sanitize score to prevent inf/nan values
                context.sender_phishing_score = 0.0 if (math.isnan(raw_score) or math.isinf(raw_score)) else max(0.0, min(1.0, raw_score))
                label = first_result.get("label", "").lower()
                context.sender_is_phishing = "phishing" in label or "malicious" in label or context.sender_phishing_score > 0.5
            else:
                context.sender_phishing_score = 0.0
                context.sender_is_phishing = False
        except Exception as e:
            logger.error(f"Error in sender phishing detection: {str(e)}", exc_info=True)
            context.sender_phishing_score = 0.0
            context.sender_is_phishing = False