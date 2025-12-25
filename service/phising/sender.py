import typing
from dataclasses import dataclass

from transformers import pipeline

from service.context import Context
from service.validator import Validator


class Sender(Validator):
    def __init__(self):
        self.pipeline = pipeline("text-classification", model="kamikaze20/phishing-email-detection_sender")

    def validate(self, param: Context) -> None:
        ret:list[dict[str, typing.Any]] = self.pipeline(param.email_request.from_)

        print(ret)