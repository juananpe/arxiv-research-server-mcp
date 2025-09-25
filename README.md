# Arxiv Research Server MCP

## Create a venv and install the requirements

Install uv if you haven't done so yet:

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
````

In Windows:

```powershell
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
```

Or you can also install uv via pip:

```bash
pip install uv
```

```bash
uv venv
source .venv/bin/activate # or  .venv\Scripts\activate in Windows
uv pip install -r requirements.txt
````

You can use `.vscode/mcp.json` file as an example to know how to install the server.

## Available Tools

### Tools
- `search_papers(topic: str, max_results: int = 5)`: Search for papers on arXiv based on a topic and store their information.
- `extract_info(paper_id: str)`: Search for information about a specific paper across all topic directories.

### Resources
- `papers://folders` → `get_available_folders()`: List all available topic folders in the papers directory.
- `papers://{topic}` → `get_topic_papers(topic: str)`: Get detailed information about papers on a specific topic.

### Prompts
- `generate_search_prompt(topic: str, num_papers: int = 5)`: Generate a prompt to find and discuss academic papers on a specific topic.

