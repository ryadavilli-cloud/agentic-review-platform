#MCP vs Native

## What was done?
- Two tools used - semgrep and pip-audit. 
- semgrep is invoked natively, pip-audit is invoked via an MCP server. 
- There is a Base Tool abstract class and the SemgrepTool and the PipAuditTool were derived from this. 
- This kept the interface from agent -> tools the same, and allowed for the tools to have their independent implementation.

## Experience
- Semgrep calls were easily auditable via the logging and print statements.
- Debugging was tougher. For the pip-audit server, I had to introduce a file based logging/debug statements to push my changes. 
- Realised the the stdin needs to be set to devnull for the async cli tool to work. This was needed to overwrite any defaults for a commandline process.
- Setting up the mcp server was easy. However, working on the integration had challenges, were I had to convert from a sub process to an asyncio process. 
- The execution of the actual tool remained the same. 
## Performance 
- Numbers below are from development experience. 
- Semgrep being native took around 6-7 seconds to complete each run. THe tool invocation and the results transform overall took around 14 seconds. 
- However, within the development experience, the results from the MCP server did take longer. 
- In addition, the startup of the mcp server and then getting the results took time to get. 
- The execution of pip-audit took upto 60 seconds to complete. 
- There were areound 2-5 seconds of the startup of the mcp server and the stdio handshake. 

## Why MCP?
- Use Native tools and MCP protocol to understand the differences, and not jsut stick to a single approach. 
- Try out tool discovery, using a standardized protocol for invoking. 
- The same server can be re-used for other cases - expand on the pip-audit functionality if needed or may be expanded to other internal tools if needed. 
- This can make the MCP server extensible for change in functionality. Better abstraction. 

## Semgrep
- Direct invocation was easier to handle. 

## What to use when?
- Recommend MCP for most cases, because the actual execution of the tools especially via CLI is the same.
-  If a different tool is needed where it may be something different from CLI execution, the abstraction of the tool implementation through the MCP server, provides the agents a flexibility in keeping their code the same. 
-  If the agents are simpler or smaller in scale, then a native tool would work better considering the performance gains and setup seen above. 