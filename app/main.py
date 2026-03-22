from fastapi import FastAPI

app = FastAPI(
    title="Agentic Engineering Review Platform",
    description="AI-powered code and risk review agent",
    version="0.1.0",
)


@app.get("/health")
def health_check():
    return {"status": "healthy", "version": "0.1.0"}
