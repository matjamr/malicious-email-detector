import typing

from transformers import pipeline

from service.context import Context
from service.validator import Validator


class MaliciousUrlDetector(Validator):
    def __init__(self):
        self.pipeline = pipeline("text-classification", model="kmack/malicious-url-detection")

    def validate(self, param: Context) -> None:
        ret:list[dict[str, typing.Any]] = self.pipeline(param.email_request.body)

        print(ret)