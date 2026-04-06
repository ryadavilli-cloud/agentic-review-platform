import logging
from abc import ABC, abstractmethod

from app.models.tools import ToolResult


class BaseTool(ABC):
    @abstractmethod
    async def run(self, target_path: str) -> ToolResult:
        pass

    @property
    @abstractmethod
    def tool_name(self) -> str:
        pass

    @property
    @abstractmethod
    def description(self) -> str:
        pass

    @property
    @abstractmethod
    def target_file(self) -> str | None:
        pass

    def common_logger(self, message: str) -> None:
        logger = logging.getLogger(self.tool_name)
        logger.info(message)
