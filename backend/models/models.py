from dataclasses import dataclass, field, asdict
from typing import List, Optional, Dict, Any
from datetime import datetime


# ============================================================================
# Request Models
# ============================================================================

@dataclass
class AttachmentRequest:
    """Request model for email attachment
    
    bytes should be base64 encoded string for JSON transmission
    """
    filename: str
    size: int
    content_type: str
    bytes: Optional[str] = None  # base64 encoded file bytes


@dataclass
class EmailRequest:
    """Request model for email analysis"""
    subject: Optional[str] = None
    body: Optional[str] = None
    from_: Optional[str] = None
    to: Optional[str] = None
    cc: Optional[List[str]] = field(default_factory=list)
    bcc: Optional[List[str]] = field(default_factory=list)
    reply_to: Optional[str] = None
    date: Optional[str] = None
    attachments: Optional[List[AttachmentRequest]] = field(default_factory=list)
    headers: Optional[Dict[str, str]] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary format expected by analyzer"""
        result = {}
        if self.subject is not None:
            result["subject"] = self.subject
        if self.body is not None:
            result["body"] = self.body
        if self.from_ is not None:
            result["from"] = self.from_
        if self.to is not None:
            result["to"] = self.to
        if self.cc:
            result["cc"] = self.cc
        if self.bcc:
            result["bcc"] = self.bcc
        if self.reply_to is not None:
            result["reply_to"] = self.reply_to
        if self.date is not None:
            result["date"] = self.date
        if self.attachments:
            result["attachments"] = [asdict(att) for att in self.attachments]
        if self.headers:
            result["headers"] = self.headers
        return result
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'EmailRequest':
        """Create EmailRequest from dictionary"""
        attachments = []
        if data.get("attachments"):
            attachments = [
                AttachmentRequest(
                    filename=att.get("filename", ""),
                    size=att.get("size", 0),
                    content_type=att.get("content_type", ""),
                    bytes=att.get("bytes")  # base64 encoded string
                )
                for att in data["attachments"]
            ]
        
        return cls(
            subject=data.get("subject"),
            body=data.get("body"),
            from_=data.get("from"),
            to=data.get("to"),
            cc=data.get("cc", []),
            bcc=data.get("bcc", []),
            reply_to=data.get("reply_to"),
            date=data.get("date"),
            attachments=attachments,
            headers=data.get("headers", {})
        )


@dataclass
class BatchEmailRequest:
    """Request model for batch email analysis"""
    emails: List[EmailRequest]
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'BatchEmailRequest':
        """Create BatchEmailRequest from dictionary"""
        emails = [
            EmailRequest.from_dict(email_data)
            for email_data in data.get("emails", [])
        ]
        return cls(emails=emails)


# ============================================================================
# Response Models
# ============================================================================

@dataclass
class MetadataAnalysis:
    """Response model for metadata analysis"""
    date: Optional[str]
    date_valid: bool
    headers: Dict[str, str]
    header_count: int
    has_message_id: bool
    has_return_path: bool
    has_received: bool
    parsed_date: Optional[str] = None


@dataclass
class ContentAnalysis:
    """Response model for content analysis"""
    subject: str
    subject_length: int
    subject_uppercase_ratio: float
    subject_has_suspicious_keywords: bool
    subject_suspicious_keywords: List[str]
    subject_has_urls: bool
    subject_urls: List[str]
    body_length: int
    body_word_count: int
    body_has_urls: bool
    body_urls: List[str]
    body_has_suspicious_keywords: bool
    body_suspicious_keywords: List[str]
    body_has_html: bool
    body_has_images: bool


@dataclass
class SenderAnalysis:
    """Response model for sender analysis"""
    from_: str
    from_valid: bool
    from_domain: Optional[str]
    from_local_part: Optional[str]
    reply_to: str
    reply_to_different: bool
    has_display_name: bool
    display_name: Optional[str]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary with 'from' key"""
        result = asdict(self)
        result["from"] = result.pop("from_")
        return result


@dataclass
class RecipientAnalysis:
    """Response model for recipient analysis"""
    to_count: int
    to_addresses: List[str]
    cc_count: int
    cc_addresses: List[str]
    bcc_count: int
    bcc_addresses: List[str]
    total_recipients: int
    unique_domains: List[str]
    unique_domain_count: int
    has_cc: bool
    has_bcc: bool


@dataclass
class AttachmentFileInfo:
    """Response model for attachment file information"""
    filename: str
    size: int
    content_type: str
    extension: str


@dataclass
class AttachmentAnalysis:
    """Response model for attachment analysis"""
    count: int
    total_size: int
    files: List[AttachmentFileInfo]
    has_executables: bool
    has_scripts: bool
    suspicious_extensions: List[str]
    executable_extensions: List[str]
    script_extensions: List[str]


@dataclass
class SecurityAnalysis:
    """Response model for security analysis"""
    suspicious_indicators: List[str]
    risk_level: str  # "low", "medium", "high"
    flags: List[str]


@dataclass
class EmailAnalysisResponse:
    """Complete response model for email analysis"""
    timestamp: str
    metadata: MetadataAnalysis
    content_analysis: ContentAnalysis
    sender_analysis: SenderAnalysis
    recipient_analysis: RecipientAnalysis
    attachment_analysis: AttachmentAnalysis
    security_analysis: SecurityAnalysis
    overall_score: int
    error: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        result = {
            "timestamp": self.timestamp,
            "metadata": asdict(self.metadata),
            "content_analysis": asdict(self.content_analysis),
            "sender_analysis": self.sender_analysis.to_dict(),
            "recipient_analysis": asdict(self.recipient_analysis),
            "attachment_analysis": asdict(self.attachment_analysis),
            "security_analysis": asdict(self.security_analysis),
            "overall_score": self.overall_score
        }
        if self.error:
            result["error"] = self.error
        return result
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'EmailAnalysisResponse':
        """Create EmailAnalysisResponse from dictionary"""
        # Convert metadata
        metadata_dict = data.get("metadata", {})
        metadata = MetadataAnalysis(
            date=metadata_dict.get("date"),
            date_valid=metadata_dict.get("date_valid", False),
            headers=metadata_dict.get("headers", {}),
            header_count=metadata_dict.get("header_count", 0),
            has_message_id=metadata_dict.get("has_message_id", False),
            has_return_path=metadata_dict.get("has_return_path", False),
            has_received=metadata_dict.get("has_received", False),
            parsed_date=metadata_dict.get("parsed_date")
        )
        
        # Convert content analysis
        content_dict = data.get("content_analysis", {})
        content = ContentAnalysis(
            subject=content_dict.get("subject", ""),
            subject_length=content_dict.get("subject_length", 0),
            subject_uppercase_ratio=content_dict.get("subject_uppercase_ratio", 0.0),
            subject_has_suspicious_keywords=content_dict.get("subject_has_suspicious_keywords", False),
            subject_suspicious_keywords=content_dict.get("subject_suspicious_keywords", []),
            subject_has_urls=content_dict.get("subject_has_urls", False),
            subject_urls=content_dict.get("subject_urls", []),
            body_length=content_dict.get("body_length", 0),
            body_word_count=content_dict.get("body_word_count", 0),
            body_has_urls=content_dict.get("body_has_urls", False),
            body_urls=content_dict.get("body_urls", []),
            body_has_suspicious_keywords=content_dict.get("body_has_suspicious_keywords", False),
            body_suspicious_keywords=content_dict.get("body_suspicious_keywords", []),
            body_has_html=content_dict.get("body_has_html", False),
            body_has_images=content_dict.get("body_has_images", False)
        )
        
        # Convert sender analysis
        sender_dict = data.get("sender_analysis", {})
        sender = SenderAnalysis(
            from_=sender_dict.get("from", ""),
            from_valid=sender_dict.get("from_valid", False),
            from_domain=sender_dict.get("from_domain"),
            from_local_part=sender_dict.get("from_local_part"),
            reply_to=sender_dict.get("reply_to", ""),
            reply_to_different=sender_dict.get("reply_to_different", False),
            has_display_name=sender_dict.get("has_display_name", False),
            display_name=sender_dict.get("display_name")
        )
        
        # Convert recipient analysis
        recipient_dict = data.get("recipient_analysis", {})
        recipient = RecipientAnalysis(
            to_count=recipient_dict.get("to_count", 0),
            to_addresses=recipient_dict.get("to_addresses", []),
            cc_count=recipient_dict.get("cc_count", 0),
            cc_addresses=recipient_dict.get("cc_addresses", []),
            bcc_count=recipient_dict.get("bcc_count", 0),
            bcc_addresses=recipient_dict.get("bcc_addresses", []),
            total_recipients=recipient_dict.get("total_recipients", 0),
            unique_domains=recipient_dict.get("unique_domains", []),
            unique_domain_count=recipient_dict.get("unique_domain_count", 0),
            has_cc=recipient_dict.get("has_cc", False),
            has_bcc=recipient_dict.get("has_bcc", False)
        )
        
        # Convert attachment analysis
        attachment_dict = data.get("attachment_analysis", {})
        files = [
            AttachmentFileInfo(
                filename=f.get("filename", ""),
                size=f.get("size", 0),
                content_type=f.get("content_type", ""),
                extension=f.get("extension", "")
            )
            for f in attachment_dict.get("files", [])
        ]
        attachment = AttachmentAnalysis(
            count=attachment_dict.get("count", 0),
            total_size=attachment_dict.get("total_size", 0),
            files=files,
            has_executables=attachment_dict.get("has_executables", False),
            has_scripts=attachment_dict.get("has_scripts", False),
            suspicious_extensions=attachment_dict.get("suspicious_extensions", []),
            executable_extensions=attachment_dict.get("executable_extensions", []),
            script_extensions=attachment_dict.get("script_extensions", [])
        )
        
        # Convert security analysis
        security_dict = data.get("security_analysis", {})
        security = SecurityAnalysis(
            suspicious_indicators=security_dict.get("suspicious_indicators", []),
            risk_level=security_dict.get("risk_level", "low"),
            flags=security_dict.get("flags", [])
        )
        
        return cls(
            timestamp=data.get("timestamp", datetime.now().isoformat()),
            metadata=metadata,
            content_analysis=content,
            sender_analysis=sender,
            recipient_analysis=recipient,
            attachment_analysis=attachment,
            security_analysis=security,
            overall_score=data.get("overall_score", 0),
            error=data.get("error")
        )


@dataclass
class HealthCheckResponse:
    """Response model for health check"""
    status: str
    service: str
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ErrorResponse:
    """Response model for error responses"""
    error: str
    message: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        result = {"error": self.error}
        if self.message:
            result["message"] = self.message
        return result


@dataclass
class BatchAnalysisResponse:
    """Response model for batch email analysis"""
    total: int
    results: List[EmailAnalysisResponse]
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "total": self.total,
            "results": [result.to_dict() for result in self.results]
        }


