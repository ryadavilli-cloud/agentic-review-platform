from pydantic import BaseModel


class AnalyzeRequest(BaseModel):
    scenario_id: str

    model_config = {"json_schema_extra": {"examples": [{"scenario_id": "pack-a"}]}}


class DemoScenarioModel(BaseModel):
    id: str
    name: str
    description: str
    path: str

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "id": "pack-a",
                    "name": "Vulnerable Python Service",
                    "description": "Flask app with seeded security issues "
                    "and vulnerable dependencies",
                    "path": "demo-packs/pack-a",
                }
            ]
        }
    }


class DemoScenarioResponseModel(BaseModel):
    id: str
    name: str
    description: str
    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "id": "pack-a",
                    "name": "Vulnerable Python Service",
                    "description": "Flask app with seeded security issues "
                    "and vulnerable dependencies",
                }
            ]
        }
    }
