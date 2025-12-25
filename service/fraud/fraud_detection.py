import typing
from dataclasses import dataclass

from transformers import pipeline

from service.context import Context
from service.validator import Validator


class FraudDetection(Validator):
    def __init__(self):
        self.pipeline = pipeline("text-classification", model="tush9905/email_fraud_detector")

    def validate(self, param: Context) -> None:
        ret:list[dict[str, typing.Any]] = self.pipeline(param.email_request.body)

        print(ret)