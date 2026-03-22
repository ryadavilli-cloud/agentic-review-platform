import os

from dotenv import load_dotenv
from openai import OpenAI

load_dotenv()

api_key = os.getenv("OPENAI_API_KEY")
llm_model = os.getenv("LLM_MODEL")
print(f"API key loaded: {'Yes' if api_key else 'No'}")
print(f"API key starts with: {api_key[:8] if api_key else 'N/A'}...")

try:
    client = OpenAI(api_key=api_key)
    response = client.chat.completions.create(
        model=llm_model,
        messages=[{"role": "user", "content": "Say hello in one word."}],
        max_tokens=10,
    )
    print(f"Response: {response.choices[0].message.content}")
    print(f"Tokens used: {response.usage.total_tokens}")
except Exception as e:
    print(f"Error: {type(e).__name__}: {e}")
