from pydantic import BaseModel


class Vulnerability(BaseModel):
    id: str
    fix_versions: list[str] = []
    aliases: list[str] = []
    description: str | None = None


class Dependency(BaseModel):
    name: str
    version: str
    vulns: list[Vulnerability] = []


class DependencyScanResult(BaseModel):
    dependencies: list[Dependency] = []
