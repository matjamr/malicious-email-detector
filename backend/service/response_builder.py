"""
Response builder to aggregate context results into EmailAnalysisResponse
"""
import re
import logging
from datetime import datetime
from typing import List, Optional
from email.utils import parseaddr, parsedate_tz
from dateutil import parser as date_parser

from models.models import (
    EmailAnalysisResponse,
    MetadataAnalysis,
    ContentAnalysis,
    SenderAnalysis,
    RecipientAnalysis,
    AttachmentAnalysis,
    AttachmentFileInfo,
    SecurityAnalysis
)
from service.context import Context

logger = logging.getLogger(__name__)


class ResponseBuilder:
    """Builds EmailAnalysisResponse from Context"""
    
    @staticmethod
    def build(context: Context) -> EmailAnalysisResponse:
        """Build complete EmailAnalysisResponse from context"""
        timestamp = datetime.now().isoformat()
        
        # Build metadata analysis
        metadata = ResponseBuilder._build_metadata(context)
        
        # Build content analysis
        content = ResponseBuilder._build_content(context)
        
        # Build sender analysis
        sender = ResponseBuilder._build_sender(context)
        
        # Build recipient analysis
        recipient = ResponseBuilder._build_recipient(context)
        
        # Build attachment analysis
        attachment = ResponseBuilder._build_attachment(context)
        
        # Build security analysis
        security = ResponseBuilder._build_security(context)
        
        # Calculate overall score
        overall_score = ResponseBuilder._calculate_overall_score(context)
        
        return EmailAnalysisResponse(
            timestamp=timestamp,
            metadata=metadata,
            content_analysis=content,
            sender_analysis=sender,
            recipient_analysis=recipient,
            attachment_analysis=attachment,
            security_analysis=security,
            overall_score=overall_score
        )
    
    @staticmethod
    def _build_metadata(context: Context) -> MetadataAnalysis:
        """Build metadata analysis"""
        email = context.email_request
        headers = email.headers or {}
        
        # Parse date
        date_valid = False
        parsed_date = None
        if email.date:
            try:
                parsed_date = date_parser.parse(email.date).isoformat()
                date_valid = True
            except Exception:
                date_valid = False
        
        return MetadataAnalysis(
            date=email.date,
            date_valid=date_valid,
            headers=headers,
            header_count=len(headers),
            has_message_id="Message-ID" in headers or "message-id" in headers,
            has_return_path="Return-Path" in headers or "return-path" in headers,
            has_received="Received" in headers or "received" in headers,
            parsed_date=parsed_date
        )
    
    @staticmethod
    def _build_content(context: Context) -> ContentAnalysis:
        """Build content analysis"""
        email = context.email_request
        subject = email.subject or ""
        body = email.body or ""
        
        # Subject analysis
        subject_length = len(subject)
        subject_uppercase_ratio = sum(1 for c in subject if c.isupper()) / len(subject) if subject else 0.0
        
        # Extract URLs from subject
        url_pattern = re.compile(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+')
        subject_urls = url_pattern.findall(subject)
        subject_has_urls = len(subject_urls) > 0
        
        # Suspicious keywords in subject
        suspicious_keywords = ["urgent", "act now", "click here", "limited time", "winner", "prize", 
                              "congratulations", "verify", "suspended", "account", "password"]
        subject_suspicious_keywords = [kw for kw in suspicious_keywords if kw in subject.lower()]
        subject_has_suspicious_keywords = len(subject_suspicious_keywords) > 0
        
        # Body analysis
        body_length = len(body)
        body_word_count = len(body.split()) if body else 0
        
        # Extract URLs from body
        body_urls = url_pattern.findall(body)
        if hasattr(context, 'url_detection_results'):
            # Use detected URLs from context if available
            body_urls = [r.get("url", "") for r in context.url_detection_results if r.get("url")]
        body_has_urls = len(body_urls) > 0
        
        # Suspicious keywords in body
        body_suspicious_keywords = [kw for kw in suspicious_keywords if kw in body.lower()]
        body_has_suspicious_keywords = len(body_suspicious_keywords) > 0
        
        # HTML and image detection
        body_has_html = "<html" in body.lower() or "<body" in body.lower() or "<div" in body.lower()
        body_has_images = "<img" in body.lower() or "data:image" in body.lower()
        
        return ContentAnalysis(
            subject=subject,
            subject_length=subject_length,
            subject_uppercase_ratio=subject_uppercase_ratio,
            subject_has_suspicious_keywords=subject_has_suspicious_keywords,
            subject_suspicious_keywords=subject_suspicious_keywords,
            subject_has_urls=subject_has_urls,
            subject_urls=subject_urls,
            body_length=body_length,
            body_word_count=body_word_count,
            body_has_urls=body_has_urls,
            body_urls=body_urls,
            body_has_suspicious_keywords=body_has_suspicious_keywords,
            body_suspicious_keywords=body_suspicious_keywords,
            body_has_html=body_has_html,
            body_has_images=body_has_images
        )
    
    @staticmethod
    def _build_sender(context: Context) -> SenderAnalysis:
        """Build sender analysis"""
        email = context.email_request
        from_addr = email.from_ or ""
        
        # Parse email address
        name, addr = parseaddr(from_addr)
        from_valid = "@" in addr and "." in addr.split("@")[1] if addr else False
        
        # Extract domain and local part
        from_domain = None
        from_local_part = None
        if "@" in addr:
            parts = addr.split("@", 1)
            from_local_part = parts[0]
            from_domain = parts[1] if len(parts) > 1 else None
        
        # Reply-to analysis
        reply_to = email.reply_to or ""
        reply_to_different = reply_to and reply_to != addr
        
        # Display name
        has_display_name = bool(name)
        display_name = name if name else None
        
        return SenderAnalysis(
            from_=from_addr,
            from_valid=from_valid,
            from_domain=from_domain,
            from_local_part=from_local_part,
            reply_to=reply_to,
            reply_to_different=reply_to_different,
            has_display_name=has_display_name,
            display_name=display_name
        )
    
    @staticmethod
    def _build_recipient(context: Context) -> RecipientAnalysis:
        """Build recipient analysis"""
        email = context.email_request
        
        # Parse to addresses
        to_addresses = []
        if email.to:
            if isinstance(email.to, str):
                to_addresses = [email.to]
            elif isinstance(email.to, list):
                to_addresses = email.to
        to_count = len(to_addresses)
        
        # CC addresses
        cc_addresses = email.cc or []
        cc_count = len(cc_addresses)
        
        # BCC addresses
        bcc_addresses = email.bcc or []
        bcc_count = len(bcc_addresses)
        
        # Total recipients
        total_recipients = to_count + cc_count + bcc_count
        
        # Extract unique domains
        all_addresses = to_addresses + cc_addresses + bcc_addresses
        unique_domains = set()
        for addr in all_addresses:
            if "@" in addr:
                domain = addr.split("@")[1]
                unique_domains.add(domain)
        unique_domains = list(unique_domains)
        unique_domain_count = len(unique_domains)
        
        return RecipientAnalysis(
            to_count=to_count,
            to_addresses=to_addresses,
            cc_count=cc_count,
            cc_addresses=cc_addresses,
            bcc_count=bcc_count,
            bcc_addresses=bcc_addresses,
            total_recipients=total_recipients,
            unique_domains=unique_domains,
            unique_domain_count=unique_domain_count,
            has_cc=cc_count > 0,
            has_bcc=bcc_count > 0
        )
    
    @staticmethod
    def _build_attachment(context: Context) -> AttachmentAnalysis:
        """Build attachment analysis"""
        email = context.email_request
        attachments = email.attachments or []
        
        count = len(attachments)
        total_size = sum(att.size for att in attachments)
        
        # Build file info list
        files = []
        executable_extensions = []
        script_extensions = []
        suspicious_extensions = []
        
        executable_exts = {".exe", ".bat", ".cmd", ".com", ".scr", ".msi", ".dll"}
        script_exts = {".js", ".vbs", ".ps1", ".sh", ".py", ".rb", ".pl"}
        suspicious_exts = {".zip", ".rar", ".7z", ".jar", ".app", ".deb", ".rpm"}
        
        for att in attachments:
            # Extract extension
            ext = ""
            if "." in att.filename:
                ext = "." + att.filename.rsplit(".", 1)[1].lower()
            
            files.append(AttachmentFileInfo(
                filename=att.filename,
                size=att.size,
                content_type=att.content_type,
                extension=ext
            ))
            
            if ext in executable_exts:
                executable_extensions.append(ext)
            if ext in script_exts:
                script_extensions.append(ext)
            if ext in suspicious_exts:
                suspicious_extensions.append(ext)
        
        has_executables = len(executable_extensions) > 0
        has_scripts = len(script_extensions) > 0
        
        return AttachmentAnalysis(
            count=count,
            total_size=total_size,
            files=files,
            has_executables=has_executables,
            has_scripts=has_scripts,
            suspicious_extensions=suspicious_extensions,
            executable_extensions=executable_extensions,
            script_extensions=script_extensions
        )
    
    @staticmethod
    def _build_security(context: Context) -> SecurityAnalysis:
        """Build security analysis"""
        suspicious_indicators = []
        flags = []
        
        # Check phishing scores
        if hasattr(context, 'email_body_is_phishing') and context.email_body_is_phishing:
            suspicious_indicators.append("Phishing detected in email body")
            flags.append("phishing_body")
        
        if hasattr(context, 'sender_is_phishing') and context.sender_is_phishing:
            suspicious_indicators.append("Phishing detected in sender")
            flags.append("phishing_sender")
        
        if hasattr(context, 'subject_is_phishing') and context.subject_is_phishing:
            suspicious_indicators.append("Phishing detected in subject")
            flags.append("phishing_subject")
        
        # Check fraud
        if hasattr(context, 'is_fraud') and context.is_fraud:
            suspicious_indicators.append("Fraud detected")
            flags.append("fraud")
        
        # Check malicious URLs
        if hasattr(context, 'malicious_url_count') and context.malicious_url_count > 0:
            suspicious_indicators.append(f"{context.malicious_url_count} malicious URL(s) detected")
            flags.append("malicious_urls")
        
        # Check malware in attachments
        if hasattr(context, 'malware_detection_results'):
            malicious_attachments = [r for r in context.malware_detection_results 
                                   if r.get("is_malicious", False)]
            if malicious_attachments:
                suspicious_indicators.append(f"{len(malicious_attachments)} malicious attachment(s) detected")
                flags.append("malware")
        
        # Determine risk level
        risk_level = "low"
        if len(flags) >= 3:
            risk_level = "high"
        elif len(flags) >= 1:
            risk_level = "medium"
        
        return SecurityAnalysis(
            suspicious_indicators=suspicious_indicators,
            risk_level=risk_level,
            flags=flags
        )
    
    @staticmethod
    def _calculate_overall_score(context: Context) -> int:
        """Calculate overall risk score (0-100)"""
        score = 0
        
        # Base score from phishing detection (0-30 points)
        if hasattr(context, 'email_body_phishing_score'):
            score += int(context.email_body_phishing_score * 30)
        
        if hasattr(context, 'sender_phishing_score'):
            score += int(context.sender_phishing_score * 20)
        
        if hasattr(context, 'subject_phishing_score'):
            score += int(context.subject_phishing_score * 15)
        
        # Fraud detection (0-20 points)
        if hasattr(context, 'fraud_score'):
            score += int(context.fraud_score * 20)
        
        # Malicious URLs (0-15 points)
        if hasattr(context, 'malicious_url_count'):
            score += min(context.malicious_url_count * 5, 15)
        
        # Malware in attachments (0-20 points)
        if hasattr(context, 'malware_detection_results'):
            for result in context.malware_detection_results:
                if result.get("is_malicious", False):
                    confidence = result.get("confidence", 0.0)
                    score += int(confidence * 20)
                    break  # Only count first malicious attachment
        
        # Cap at 100
        score = min(score, 100)
        
        return score

