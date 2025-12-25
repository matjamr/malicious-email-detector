from models.models import AttachmentRequest, EmailRequest


class Context:
    def __init__(self, email_request: EmailRequest):
        self.email_request = email_request