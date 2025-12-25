from service.context import Context
from abc import ABC, abstractmethod

class Validator(ABC):
    @abstractmethod
    def validate(self, param: Context) -> None:
        pass