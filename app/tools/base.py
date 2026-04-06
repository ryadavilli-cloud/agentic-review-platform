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

    def common_logger(self, message: str) -> None:
        logger = logging.getLogger(self.tool_name)
        logger.info(message)
