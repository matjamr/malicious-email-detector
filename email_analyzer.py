import logging
import re
from datetime import datetime
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse
import email.utils

logger = logging.getLogger(__name__)


class EmailAnalyzer:
    """
    Automated class for analyzing email metadata and content.
    Analyzes subject, body, from, cc, attachments, and other email properties.
    """
    
    def __init__(self):
        """Initialize the EmailAnalyzer"""
        logger.info("Initializing EmailAnalyzer")
        self.suspicious_keywords = [
            'urgent', 'click here', 'act now', 'limited time', 'winner',
            'congratulations', 'free', 'guaranteed', 'risk-free', 'click below'
        ]
        
    def analyze(self, email_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Main analysis method that processes email data and returns comprehensive analysis
        
        Args:
            email_data: Dictionary containing email metadata and content
            
        Returns:
            Dictionary containing analysis results
        """
        logger.info("Starting email analysis")
        
        analysis = {
            "timestamp": datetime.now().isoformat(),
            "metadata": {},
            "content_analysis": {},
            "sender_analysis": {},
            "recipient_analysis": {},
            "attachment_analysis": {},
            "security_analysis": {},
            "overall_score": 0
        }
        
        try:
            # Analyze metadata
            analysis["metadata"] = self._analyze_metadata(email_data)
            
            # Analyze subject and body
            analysis["content_analysis"] = self._analyze_content(email_data)
            
            # Analyze sender
            analysis["sender_analysis"] = self._analyze_sender(email_data)
            
            # Analyze recipients
            analysis["recipient_analysis"] = self._analyze_recipients(email_data)
            
            # Analyze attachments
            analysis["attachment_analysis"] = self._analyze_attachments(email_data)
            
            # Security and spam analysis
            analysis["security_analysis"] = self._analyze_security(email_data)
            
            # Calculate overall score (0-100, higher = more suspicious)
            analysis["overall_score"] = self._calculate_risk_score(analysis)
            
            logger.info(f"Analysis completed. Risk score: {analysis['overall_score']}/100")
            
        except Exception as e:
            logger.error(f"Error during analysis: {str(e)}", exc_info=True)
            analysis["error"] = str(e)
        
        return analysis
    
    def _analyze_metadata(self, email_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze email metadata like date, headers, etc."""
        logger.debug("Analyzing metadata")
        
        metadata_analysis = {
            "date": email_data.get("date"),
            "date_valid": False,
            "headers": email_data.get("headers", {}),
            "header_count": 0,
            "has_message_id": False,
            "has_return_path": False,
            "has_received": False
        }
        
        # Check date validity
        if email_data.get("date"):
            try:
                parsed_date = email.utils.parsedate_to_datetime(email_data["date"])
                metadata_analysis["date_valid"] = True
                metadata_analysis["parsed_date"] = parsed_date.isoformat()
            except:
                pass
        
        # Analyze headers
        headers = email_data.get("headers", {})
        metadata_analysis["header_count"] = len(headers)
        metadata_analysis["has_message_id"] = "Message-ID" in headers or "message-id" in headers
        metadata_analysis["has_return_path"] = "Return-Path" in headers or "return-path" in headers
        metadata_analysis["has_received"] = "Received" in headers or "received" in headers
        
        logger.debug(f"Metadata analysis: {len(headers)} headers found")
        return metadata_analysis
    
    def _analyze_content(self, email_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze email subject and body content"""
        logger.debug("Analyzing content")
        
        subject = email_data.get("subject", "")
        body = email_data.get("body", "")
        
        content_analysis = {
            "subject": subject,
            "subject_length": len(subject),
            "subject_uppercase_ratio": self._calculate_uppercase_ratio(subject),
            "subject_has_suspicious_keywords": False,
            "subject_suspicious_keywords": [],
            "subject_has_urls": False,
            "subject_urls": [],
            "body_length": len(body),
            "body_word_count": len(body.split()) if body else 0,
            "body_has_urls": False,
            "body_urls": [],
            "body_has_suspicious_keywords": False,
            "body_suspicious_keywords": [],
            "body_has_html": "<html" in body.lower() or "<body" in body.lower(),
            "body_has_images": "<img" in body.lower() or "[image:" in body.lower()
        }
        
        # Check for suspicious keywords in subject
        subject_lower = subject.lower()
        for keyword in self.suspicious_keywords:
            if keyword in subject_lower:
                content_analysis["subject_has_suspicious_keywords"] = True
                content_analysis["subject_suspicious_keywords"].append(keyword)
        
        # Extract URLs from subject
        subject_urls = self._extract_urls(subject)
        if subject_urls:
            content_analysis["subject_has_urls"] = True
            content_analysis["subject_urls"] = subject_urls
        
        # Check for suspicious keywords in body
        body_lower = body.lower()
        for keyword in self.suspicious_keywords:
            if keyword in body_lower:
                content_analysis["body_has_suspicious_keywords"] = True
                content_analysis["body_suspicious_keywords"].append(keyword)
        
        # Extract URLs from body
        body_urls = self._extract_urls(body)
        if body_urls:
            content_analysis["body_has_urls"] = True
            content_analysis["body_urls"] = body_urls
        
        logger.debug(f"Content analysis: subject={len(subject)} chars, body={len(body)} chars")
        return content_analysis
    
    def _analyze_sender(self, email_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze email sender information"""
        logger.debug("Analyzing sender")
        
        sender = email_data.get("from", "")
        reply_to = email_data.get("reply_to", "")
        
        sender_analysis = {
            "from": sender,
            "from_valid": False,
            "from_domain": None,
            "from_local_part": None,
            "reply_to": reply_to,
            "reply_to_different": False,
            "has_display_name": False,
            "display_name": None
        }
        
        # Parse sender email
        if sender:
            parsed_sender = email.utils.parseaddr(sender)
            sender_analysis["display_name"] = parsed_sender[0]
            sender_email = parsed_sender[1]
            
            if sender_email:
                sender_analysis["from_valid"] = self._is_valid_email(sender_email)
                if "@" in sender_email:
                    parts = sender_email.split("@")
                    sender_analysis["from_local_part"] = parts[0]
                    sender_analysis["from_domain"] = parts[1] if len(parts) > 1 else None
                
                sender_analysis["has_display_name"] = bool(parsed_sender[0])
                
                # Check if reply-to is different from from
                if reply_to:
                    parsed_reply_to = email.utils.parseaddr(reply_to)
                    reply_to_email = parsed_reply_to[1]
                    sender_analysis["reply_to_different"] = sender_email.lower() != reply_to_email.lower()
        
        logger.debug(f"Sender analysis: from={sender}, domain={sender_analysis.get('from_domain')}")
        return sender_analysis
    
    def _analyze_recipients(self, email_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze email recipients (to, cc, bcc)"""
        logger.debug("Analyzing recipients")
        
        to = email_data.get("to", "")
        cc = email_data.get("cc", [])
        bcc = email_data.get("bcc", [])
        
        # Normalize to list
        if isinstance(to, str):
            to = [to] if to else []
        if isinstance(cc, str):
            cc = [cc] if cc else []
        if isinstance(bcc, str):
            bcc = [bcc] if bcc else []
        
        recipient_analysis = {
            "to_count": len(to),
            "to_addresses": to,
            "cc_count": len(cc),
            "cc_addresses": cc,
            "bcc_count": len(bcc),
            "bcc_addresses": bcc,
            "total_recipients": len(to) + len(cc) + len(bcc),
            "unique_domains": set(),
            "has_cc": len(cc) > 0,
            "has_bcc": len(bcc) > 0
        }
        
        # Extract unique domains
        all_recipients = to + cc + bcc
        for recipient in all_recipients:
            if isinstance(recipient, str):
                parsed = email.utils.parseaddr(recipient)
                email_addr = parsed[1] if parsed[1] else parsed[0]
                if "@" in email_addr:
                    domain = email_addr.split("@")[1]
                    recipient_analysis["unique_domains"].add(domain)
        
        recipient_analysis["unique_domains"] = list(recipient_analysis["unique_domains"])
        recipient_analysis["unique_domain_count"] = len(recipient_analysis["unique_domains"])
        
        logger.debug(f"Recipient analysis: {recipient_analysis['total_recipients']} total recipients")
        return recipient_analysis
    
    def _analyze_attachments(self, email_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze email attachments"""
        logger.debug("Analyzing attachments")
        
        attachments = email_data.get("attachments", [])
        
        attachment_analysis = {
            "count": len(attachments),
            "total_size": 0,
            "files": [],
            "has_executables": False,
            "has_scripts": False,
            "suspicious_extensions": [],
            "executable_extensions": [".exe", ".bat", ".cmd", ".com", ".pif", ".scr", ".vbs", ".js"],
            "script_extensions": [".js", ".vbs", ".ps1", ".sh", ".py"]
        }
        
        for attachment in attachments:
            filename = attachment.get("filename", "")
            size = attachment.get("size", 0)
            content_type = attachment.get("content_type", "")
            
            file_info = {
                "filename": filename,
                "size": size,
                "content_type": content_type,
                "extension": self._get_extension(filename)
            }
            
            attachment_analysis["files"].append(file_info)
            attachment_analysis["total_size"] += size
            
            # Check for suspicious extensions
            ext = file_info["extension"].lower()
            if ext in attachment_analysis["executable_extensions"]:
                attachment_analysis["has_executables"] = True
                attachment_analysis["suspicious_extensions"].append(ext)
            elif ext in attachment_analysis["script_extensions"]:
                attachment_analysis["has_scripts"] = True
                attachment_analysis["suspicious_extensions"].append(ext)
        
        logger.debug(f"Attachment analysis: {len(attachments)} attachments, {attachment_analysis['total_size']} bytes")
        return attachment_analysis
    
    def _analyze_security(self, email_data: Dict[str, Any]) -> Dict[str, Any]:
        """Perform security and spam analysis"""
        logger.debug("Analyzing security")
        
        security_analysis = {
            "suspicious_indicators": [],
            "risk_level": "low",
            "flags": []
        }
        
        # Collect various security indicators
        subject = email_data.get("subject", "").lower()
        body = email_data.get("body", "").lower()
        sender = email_data.get("from", "").lower()
        attachments = email_data.get("attachments", [])
        
        # Check for suspicious patterns
        if len(subject) > 100:
            security_analysis["flags"].append("Long subject line")
        
        if subject.count("!") > 3:
            security_analysis["suspicious_indicators"].append("Multiple exclamation marks in subject")
            security_analysis["flags"].append("Excessive punctuation")
        
        if self._extract_urls(subject + " " + body):
            security_analysis["suspicious_indicators"].append("URLs in email content")
            security_analysis["flags"].append("Contains URLs")
        
        if any(att.get("filename", "").endswith((".exe", ".bat", ".vbs")) for att in attachments):
            security_analysis["suspicious_indicators"].append("Executable attachments")
            security_analysis["flags"].append("Executable files")
            security_analysis["risk_level"] = "high"
        
        if not email_data.get("headers", {}).get("Message-ID"):
            security_analysis["flags"].append("Missing Message-ID header")
        
        # Determine overall risk level
        if len(security_analysis["suspicious_indicators"]) >= 3:
            security_analysis["risk_level"] = "high"
        elif len(security_analysis["suspicious_indicators"]) >= 1:
            security_analysis["risk_level"] = "medium"
        
        logger.debug(f"Security analysis: risk_level={security_analysis['risk_level']}, {len(security_analysis['flags'])} flags")
        return security_analysis
    
    def _calculate_risk_score(self, analysis: Dict[str, Any]) -> int:
        """Calculate overall risk score (0-100)"""
        score = 0
        
        # Content analysis scoring
        content = analysis.get("content_analysis", {})
        if content.get("subject_has_suspicious_keywords"):
            score += 15
        if content.get("subject_has_urls"):
            score += 10
        if content.get("body_has_suspicious_keywords"):
            score += 20
        if content.get("body_has_urls"):
            score += 15
        if content.get("subject_uppercase_ratio", 0) > 0.5:
            score += 10
        
        # Attachment scoring
        attachments = analysis.get("attachment_analysis", {})
        if attachments.get("has_executables"):
            score += 30
        if attachments.get("has_scripts"):
            score += 20
        if attachments.get("count", 0) > 5:
            score += 10
        
        # Security scoring
        security = analysis.get("security_analysis", {})
        if security.get("risk_level") == "high":
            score += 25
        elif security.get("risk_level") == "medium":
            score += 15
        
        # Sender analysis
        sender = analysis.get("sender_analysis", {})
        if sender.get("reply_to_different"):
            score += 10
        
        return min(score, 100)  # Cap at 100
    
    def _calculate_uppercase_ratio(self, text: str) -> float:
        """Calculate ratio of uppercase letters"""
        if not text:
            return 0.0
        uppercase_count = sum(1 for c in text if c.isupper())
        return uppercase_count / len(text) if len(text) > 0 else 0.0
    
    def _extract_urls(self, text: str) -> List[str]:
        """Extract URLs from text"""
        url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        urls = re.findall(url_pattern, text)
        return urls
    
    def _is_valid_email(self, email: str) -> bool:
        """Basic email validation"""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, email))
    
    def _get_extension(self, filename: str) -> str:
        """Get file extension from filename"""
        if "." in filename:
            return "." + filename.rsplit(".", 1)[1].lower()
        return ""


