# Realistic MCP config fixture provenance

`modelcontextprotocol-docs.mcp.json` is a small, frozen copy of the public
`.mcp.json` example in the official MCP servers repository:

https://github.com/modelcontextprotocol/servers/blob/main/.mcp.json

Retrieved on 2026-10-10. It is used only to test that the scanner recognizes
a real remote HTTP server configuration and does not report a schema error.
This fixture is not a security verdict about the remote server.

vscode-mixed-servers.mcp.json is an adapted fixture based on configuration examples in the official VS Code MCP configuration reference:
https://code.visualstudio.com/docs/agents/reference/mcp-configuration

It combines the documented top-level servers structure, HTTP authorization header input reference, and stdio server shape to test end-to-end parsing. Placeholder domains and credentials are intentionally non-secret; the fixture is a regression case, not an assessment of any service.
