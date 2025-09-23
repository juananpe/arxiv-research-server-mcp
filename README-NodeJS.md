# ArXiv Research Server MCP (Node.js)

A Model Context Protocol (MCP) server for searching and managing academic papers from arXiv, implemented in Node.js with Express.

## Features

- **Search Papers**: Search for academic papers on arXiv by topic
- **Extract Info**: Retrieve detailed information about specific papers
- **Resource Management**: Access papers organized by topic
- **OAuth 2.0 Authentication**: Secure API access with OAuth2/PKCE support
- **Streamable HTTP Transport**: Real-time communication via HTTP with SSE support

## Prerequisites

- Node.js (v16 or higher)
- npm

## Installation

1. Install Node.js and npm:
```bash
# On Ubuntu/Debian
sudo apt update && sudo apt install -y nodejs npm

# On macOS
brew install node

# On Windows
# Download from https://nodejs.org/
```

2. Install dependencies:
```bash
npm install
```

3. Configure environment variables:
Edit the `.env` file with your OAuth settings and other configuration.

## Usage

### Starting the Server

```bash
npm start
# or for development with auto-restart
npm run dev
```

The server will start on port 3001 by default (configurable via PORT environment variable).

### API Endpoints

- `GET /` - Server information and capabilities
- `GET /health` - Health check endpoint
- `POST /mcp` - MCP protocol endpoint (requires authentication)
- `GET /mcp` - MCP SSE stream endpoint (requires authentication)
- `DELETE /mcp` - Terminate MCP session (requires authentication)

### OAuth Endpoints

- `GET /.well-known/oauth-authorization-server` - OAuth server metadata
- `GET /.well-known/oauth-protected-resource` - Protected resource metadata
- `GET /authorize` - OAuth authorization endpoint
- `POST /token` - OAuth token endpoint
- `GET /callback` - OAuth callback endpoint
- `GET /tokeninfo` - Token information (for debugging)

## MCP Tools

### search_papers
Search for papers on arXiv based on a topic.

**Parameters:**
- `topic` (string): The topic to search for
- `max_results` (number, optional): Maximum number of results (default: 5)

**Returns:** List of paper IDs found in the search

### extract_info
Retrieve information about a specific paper.

**Parameters:**
- `paper_id` (string): The ID of the paper to look for

**Returns:** JSON string with paper information or error message

## MCP Resources

### papers://folders
List all available topic folders.

**Returns:** Markdown list of available topics

### papers://{topic}
Get detailed information about papers on a specific topic.

**Parameters:**
- `topic` (string): The research topic

**Returns:** Markdown content with paper details

## MCP Prompts

### generate_search_prompt
Generate a prompt for Claude to find and discuss academic papers.

**Parameters:**
- `topic` (string): The research topic
- `num_papers` (number, optional): Number of papers to search for (default: 5)

**Returns:** Formatted prompt text

## Authentication

The server uses OAuth 2.0 with PKCE (Proof Key for Code Exchange) for secure API access. Required scopes:
- `read_papers`: Access to read paper information
- `search_papers`: Permission to search for papers

## Data Storage

Papers are stored in the `papers/` directory, organized by topic:
```
papers/
├── machine_learning/
│   └── papers_info.json
├── quantum_computing/
│   └── papers_info.json
└── ...
```

## Development

### Project Structure

- `research-server.js` - Main server file
- `package.json` - Dependencies and scripts
- `.env` - Environment configuration
- `papers/` - Directory for storing paper data

### Adding New Tools/Resources

1. Register tools using `mcpServer.registerTool()`
2. Register resources using `mcpServer.registerResource()`
3. Register prompts using `mcpServer.registerPrompt()`

## Migration from Python Version

This Node.js version provides the same functionality as the original Python `research_server.py`:

- **Same MCP Tools**: `search_papers` and `extract_info`
- **Same Resources**: `papers://folders` and `papers://{topic}`
- **Same Prompt**: `generate_search_prompt`
- **Compatible Data Storage**: Uses the same `papers/` directory structure
- **OAuth 2.0 Support**: Full OAuth2/PKCE authentication like the example

### Key Differences

- **Language**: Node.js/JavaScript instead of Python
- **HTTP Framework**: Express.js instead of FastMCP's built-in server
- **Dependencies**: Uses `axios` and `xml2js` for arXiv API calls
- **Port**: Runs on port 3001 instead of 8001 (configurable)
- **File System**: Uses Node.js `fs` module instead of `os` and `json`

### Data Compatibility

The Node.js version is fully compatible with data created by the Python version. You can:
- Use existing `papers/` directories
- Access papers stored by the Python server
- Mix usage between both servers

## License

MIT