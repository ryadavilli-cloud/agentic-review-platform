import asyncio
import os
from pathlib import Path

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("pip-audit-server")


@mcp.tool()
async def scan_requirements(target_path: str) -> str:
    # Validate file existence.
    file_path = Path(target_path)

    if not file_path.is_file():
        return f"Error: File '{target_path}' not found."

    try:
        env = {**os.environ, "PYTHONUTF8": "1"}

        command = ["pip-audit", "-r", str(target_path), "-f", "json"]
        process = await asyncio.create_subprocess_exec(
            *command,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env,
        )
        stdout, stderr = await process.communicate()

        # pip-audit ran but found vulnerabilities → non-zero exit code,
        #       but stdout has valid JSON — this is success, not failure
        if stdout.decode() != "":
            return stdout.decode()

        # pip-audit genuinely failed → stderr has the error,
        #       stdout is empty or unparseable
        elif stderr.decode() != "":
            return f"Error: pip-audit failed to run. Details: {stderr.decode()}"

        return "Error: pip-audit did not return any output."

    except FileNotFoundError:
        # pip-audit not installed → catch FileNotFoundError from subprocess.run
        return "Error: pip-audit is not installed or not found in PATH."

    except Exception as e:
        return f"Error occurred while running pip-audit: {e}"


if __name__ == "__main__":
    mcp.run(transport="stdio")
