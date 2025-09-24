import { config } from "dotenv";
import {
  McpServer,
  ResourceTemplate,
} from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { z } from "zod";
import express from "express";
import { randomUUID } from "crypto";
import fs from "fs";
import path from "path";
import axios from "axios";
import xml2js from "xml2js";

// Load environment variables from .env file
config();

// Constants
const PAPER_DIR = "papers";

// Create single global MCP server instance
const mcpServer = new McpServer({
  name: "arxiv-research-server",
  version: "1.0.0",
});

// Helper function to search arXiv
async function searchArxivPapers(topic, maxResults = 5) {
  try {
    const searchQuery = topic.replace(/\s+/g, "+");
    const url = `http://export.arxiv.org/api/query?search_query=all:${searchQuery}&start=0&max_results=${maxResults}&sortBy=relevance`;

    const response = await axios.get(url);
    const parser = new xml2js.Parser();
    const result = await parser.parseStringPromise(response.data);

    const entries = result.feed.entry || [];
    return entries.map((entry) => ({
      id: entry.id[0].split("/").pop(),
      title: entry.title[0],
      authors: entry.author.map((author) => author.name[0]),
      summary: entry.summary[0],
      published: entry.published[0],
      pdf_url: entry.link.find((link) => link.$.title === "pdf").$.href,
      short_id: entry.id[0].split("/").pop(),
    }));
  } catch (error) {
    console.error("Error searching arXiv:", error);
    return [];
  }
}

// Tool: search_papers
mcpServer.registerTool(
  "search_papers",
  {
    title: "Search Papers",
    description:
      "Search for papers on arXiv based on a topic and store their information.",
    inputSchema: {
      topic: z.string().describe("The topic to search for"),
      max_results: z
        .number()
        .optional()
        .default(5)
        .describe("Maximum number of results to retrieve"),
    },
  },
  async ({ topic, max_results }) => {
    console.info(`>>> 🛠️ Tool: 'search_papers' called for '${topic}'`);

    try {
      const papers = await searchArxivPapers(topic, max_results);

      // Create directory for this topic
      const topicDir = topic.toLowerCase().replace(/\s+/g, "_");
      const dirPath = path.join(PAPER_DIR, topicDir);
      fs.mkdirSync(dirPath, { recursive: true });

      const filePath = path.join(dirPath, "papers_info.json");

      // Try to load existing papers info
      let papersInfo = {};
      try {
        const existingData = fs.readFileSync(filePath, "utf8");
        papersInfo = JSON.parse(existingData);
      } catch (error) {
        // File doesn't exist or is invalid, start fresh
      }

      // Process each paper and add to papers_info
      const paperIds = [];
      for (const paper of papers) {
        paperIds.push(paper.short_id);
        const paperInfo = {
          title: paper.title,
          authors: paper.authors,
          summary: paper.summary,
          pdf_url: paper.pdf_url,
          published: paper.published.split("T")[0], // Get date part only
        };
        papersInfo[paper.short_id] = paperInfo;
      }

      // Save updated papers_info to json file
      fs.writeFileSync(filePath, JSON.stringify(papersInfo, null, 2));

      console.log(`Results saved in: ${filePath}`);

      return {
        content: [{ type: "text", text: JSON.stringify(paperIds, null, 2) }],
      };
    } catch (error) {
      console.error("Error in search_papers:", error);
      return {
        content: [
          { type: "text", text: `Error searching papers: ${error.message}` },
        ],
      };
    }
  }
);

// Tool: extract_info
mcpServer.registerTool(
  "extract_info",
  {
    title: "Extract Info",
    description:
      "Search for information about a specific paper across all topic directories.",
    inputSchema: {
      paper_id: z.string().describe("The ID of the paper to look for"),
    },
  },
  async ({ paper_id }) => {
    console.info(`>>> 🛠️ Tool: 'extract_info' called for '${paper_id}'`);

    try {
      // Get all topic directories
      const items = fs.readdirSync(PAPER_DIR);

      for (const item of items) {
        const itemPath = path.join(PAPER_DIR, item);
        const stat = fs.statSync(itemPath);

        if (stat.isDirectory()) {
          const filePath = path.join(itemPath, "papers_info.json");

          if (fs.existsSync(filePath)) {
            try {
              const data = fs.readFileSync(filePath, "utf8");
              const papersInfo = JSON.parse(data);

              if (papersInfo[paper_id]) {
                return {
                  content: [
                    {
                      type: "text",
                      text: JSON.stringify(papersInfo[paper_id], null, 2),
                    },
                  ],
                };
              }
            } catch (error) {
              console.error(`Error reading ${filePath}:`, error);
              continue;
            }
          }
        }
      }

      return {
        content: [
          {
            type: "text",
            text: `There's no saved information related to paper ${paper_id}.`,
          },
        ],
      };
    } catch (error) {
      console.error("Error in extract_info:", error);
      return {
        content: [
          { type: "text", text: `Error extracting info: ${error.message}` },
        ],
      };
    }
  }
);

// Resource: papers://folders
mcpServer.registerResource(
  "available-topics",
  "papers://folders",
  {
    title: "Available Topics",
    description: "List all available topic folders in the papers directory.",
    mimeType: "text/markdown",
  },
  async (uri) => {
    const folders = [];

    // Get all topic directories
    if (fs.existsSync(PAPER_DIR)) {
      const items = fs.readdirSync(PAPER_DIR);

      for (const item of items) {
        const itemPath = path.join(PAPER_DIR, item);
        const stat = fs.statSync(itemPath);

        if (stat.isDirectory()) {
          const papersFile = path.join(itemPath, "papers_info.json");
          if (fs.existsSync(papersFile)) {
            folders.push(item);
          }
        }
      }
    }

    // Create a simple markdown list
    let content = "# Available Topics\n\n";
    if (folders.length > 0) {
      for (const folder of folders) {
        content += `- ${folder}\n`;
      }
    } else {
      content += "No topics found.\n";
    }

    return {
      contents: [
        {
          uri: uri.href,
          text: content,
        },
      ],
    };
  }
);

// Resource: papers://{topic}
mcpServer.registerResource(
  "topic-papers",
  new ResourceTemplate("papers://{topic}", { list: undefined }),
  {
    title: "Topic Papers",
    description: "Get detailed information about papers on a specific topic.",
    mimeType: "text/markdown",
  },
  async (uri, { topic }) => {
    const topicDir = topic.toLowerCase().replace(/\s+/g, "_");
    const papersFile = path.join(PAPER_DIR, topicDir, "papers_info.json");

    if (!fs.existsSync(papersFile)) {
      const content = `# No papers found for topic: ${topic}\n\nTry searching for papers on this topic first.`;
      return {
        contents: [
          {
            uri: uri.href,
            text: content,
          },
        ],
      };
    }

    try {
      const data = fs.readFileSync(papersFile, "utf8");
      const papersData = JSON.parse(data);

      // Create markdown content with paper details
      let content = `# Papers on ${topic
        .replace(/_/g, " ")
        .replace(/\b\w/g, (l) => l.toUpperCase())}\n\n`;
      content += `Total papers: ${Object.keys(papersData).length}\n\n`;

      for (const [paperId, paperInfo] of Object.entries(papersData)) {
        content += `## ${paperInfo.title}\n`;
        content += `- **Paper ID**: ${paperId}\n`;
        content += `- **Authors**: ${paperInfo.authors.join(", ")}\n`;
        content += `- **Published**: ${paperInfo.published}\n`;
        content += `- **PDF URL**: [${paperInfo.pdf_url}](${paperInfo.pdf_url})\n\n`;
        content += `### Summary\n${paperInfo.summary.substring(0, 500)}...\n\n`;
        content += "---\n\n";
      }

      return {
        contents: [
          {
            uri: uri.href,
            text: content,
          },
        ],
      };
    } catch (error) {
      const content = `# Error reading papers data for ${topic}\n\nThe papers data file is corrupted.`;
      return {
        contents: [
          {
            uri: uri.href,
            text: content,
          },
        ],
      };
    }
  }
);

// Prompt: generate_search_prompt
mcpServer.registerPrompt(
  "generate_search_prompt",
  {
    title: "Generate Search Prompt",
    description:
      "Generate a prompt for Claude to find and discuss academic papers on a specific topic.",
    argsSchema: {
      topic: z.string().describe("The research topic"),
      num_papers: z
        .union([z.string(), z.number()])
        .optional()
        .default(5)
        .transform((val) =>
          typeof val === "string" ? parseInt(val, 10) || 5 : val
        )
        .describe("Number of papers to search for"),
    },
  },
  async ({ topic, num_papers }) => ({
    messages: [
      {
        role: "user",
        content: {
          type: "text",
          text: `Search for ${num_papers} academic papers about '${topic}' using the search_papers tool. \n\nFollow these instructions:\n1. First, search for papers using search_papers(topic='${topic}', max_results=${num_papers})\n2. For each paper found, extract and organize the following information:\n   - Paper title\n   - Authors\n   - Publication date\n   - Brief summary of the key findings\n   - Main contributions or innovations\n   - Methodologies used\n   - Relevance to the topic '${topic}'\n\n3. Provide a comprehensive summary that includes:\n   - Overview of the current state of research in '${topic}'\n   - Common themes and trends across the papers\n   - Key research gaps or areas for future investigation\n   - Most impactful or influential papers in this area\n\n4. Organize your findings in a clear, structured format with headings and bullet points for easy readability.\n\nPlease present both detailed information about each paper and a high-level synthesis of the research landscape in ${topic}.`,
        },
      },
    ],
  })
);

// Create Express app
const app = express();

// CORS middleware to allow cross-origin requests
app.use((req, res, next) => {
  res.header("Access-Control-Allow-Origin", "*");
  res.header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
  res.header(
    "Access-Control-Allow-Headers",
    "Origin, X-Requested-With, Content-Type, Accept, Authorization, mcp-session-id, mcp-protocol-version"
  );
  res.header("Access-Control-Expose-Headers", "mcp-session-id");

  // Handle preflight requests
  if (req.method === "OPTIONS") {
    return res.status(200).end();
  }

  next();
});

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Store active transport sessions
const transports = new Map(); // sessionId -> transport

// Helper to get base URL dynamically
function getBaseUrl(req) {
  const proto = req.headers["x-forwarded-proto"] || req.protocol;
  const host = req.headers["x-forwarded-host"] || req.headers.host;
  return `${proto}://${host}`;
}

// Helper to create/connect a transport for a session
async function getOrCreateTransport(sessionId) {
  if (transports.has(sessionId)) {
    return transports.get(sessionId);
  }

  const transport = new StreamableHTTPServerTransport({
    enableJsonResponse: true,
    eventSourceEnabled: true,
  });

  transport.sessionId = sessionId;
  transport.onclose = () => {
    console.log(`🗑️ Transport closed for session: ${sessionId}`);
    transports.delete(sessionId);
  };

  await mcpServer.connect(transport);
  transports.set(sessionId, transport);
  console.log(`✅ Created new transport for session: ${sessionId}`);

  return transport;
}

// Protected MCP endpoint (no auth) - uses single server instance
app.post("/mcp", async (req, res) => {
  console.log(
    `📨 POST /mcp from ${req.ip} - Method: ${req.body?.method}, Session: ${req.headers["mcp-session-id"]}`
  );
  console.log("📨 Received MCP request:", req.body);

  try {
    const body = req.body;

    const headerVal = req.headers["mcp-session-id"];
    const clientSessionId = Array.isArray(headerVal) ? headerVal[0] : headerVal;
    const isInit = body && body.method === "initialize";
    let sessionId = clientSessionId;

    if (isInit || !sessionId) {
      sessionId = randomUUID();
    }

    res.setHeader("Mcp-Session-Id", sessionId);

    const transport = await getOrCreateTransport(sessionId);

    await transport.handleRequest(req, res, body);
  } catch (error) {
    console.error("❌ Error handling MCP request:", error);
    if (!res.headersSent) {
      res.status(500).json({
        jsonrpc: "2.0",
        error: {
          code: -32603,
          message: "Internal server error",
        },
        id: null,
      });
    }
  }
});

// Handle GET requests for SSE streams (no auth)
app.get("/mcp", async (req, res) => {
  console.log(
    `📡 GET /mcp (SSE) from ${req.ip} - Session: ${req.headers["mcp-session-id"]}`
  );
  const headerVal = req.headers["mcp-session-id"];
  const sessionId = Array.isArray(headerVal) ? headerVal[0] : headerVal;

  if (!sessionId || !transports.has(sessionId)) {
    res.status(400).send("Invalid or missing session ID");
    return;
  }

  console.log(`📡 Establishing SSE stream for session ${sessionId}`);

  const transport = transports.get(sessionId);

  await transport.handleRequest(req, res);
});

// Handle DELETE requests for session termination (no auth)
app.delete("/mcp", async (req, res) => {
  console.log(
    `🗑️ DELETE /mcp from ${req.ip} - Session: ${req.headers["mcp-session-id"]}`
  );
  const headerVal = req.headers["mcp-session-id"];
  const sessionId = Array.isArray(headerVal) ? headerVal[0] : headerVal;

  if (sessionId && transports.has(sessionId)) {
    console.log(`🗑️ Cleaning up session: ${sessionId}`);
    transports.delete(sessionId);
    res.status(200).json({ success: true });
  } else {
    res.status(404).json({ error: "Session not found" });
  }
});

// Health check endpoint
app.get("/health", (req, res) => {
  console.log(`🏥 GET /health from ${req.ip}`);
  res.json({
    status: "healthy",
    server: "arxiv-research-server",
    version: "1.0.0",
    activeSessions: transports.size,
  });
});

// Server info endpoint
app.get("/", (req, res) => {
  console.log(`ℹ️ GET / from ${req.ip}`);
  const base = getBaseUrl(req);
  res.json({
    name: "ArXiv Research Server MCP (no-auth)",
    version: "1.0.0",
    description:
      "MCP server for searching and managing arXiv papers (no authentication)",
    endpoints: {
      mcp: `${base}/mcp`,
      health: `${base}/health`,
    },
    tools: ["search_papers", "extract_info"],
    resources: ["papers://folders", "papers://{topic}"],
    prompts: ["generate_search_prompt"],
    activeSessions: transports.size,
  });
});

// Shutdown helper function
async function shutdownServer() {
  console.log("\n🛑 Shutting down MCP server...");

  // Close all active transports
  for (const [sessionId, transport] of transports) {
    try {
      console.log(`🔄 Closing transport for session ${sessionId}...`);
      await transport.close();
    } catch (error) {
      console.error(
        `❌ Error closing transport for session ${sessionId}:`,
        error
      );
    }
  }

  // Clear the transports map
  transports.clear();

  console.log("✅ Server shutdown complete");
  process.exit(0);
}

// Main function to start the server
async function main() {
  try {
    const port = process.env.PORT || 3004;

    app.listen(port, () => {
      console.log(
        `🚀 MCP server (Streamable HTTP, no-auth) started on port ${port}`
      );
      console.log(`📡 MCP endpoint: http://localhost:${port}/mcp`);
      console.log(`🏥 Health check: http://localhost:${port}/health`);
      console.log(`ℹ️  Server info: http://localhost:${port}/`);
    });
  } catch (error) {
    console.error("❌ MCP server failed to start:", error);
    process.exit(1);
  }
}

// Handle graceful shutdown
process.on("SIGINT", async () => {
  await shutdownServer();
});

process.on("SIGTERM", async () => {
  await shutdownServer();
});

// Start the server
main().catch((err) => {
  console.error("❌ MCP server failed to start:", err);
  process.exit(1);
});

// Catch-all endpoint to log unexpected requests
app.use((req, res, next) => {
  console.log(
    `❓ ${req.method} ${req.path} from ${req.ip} - UNEXPECTED ENDPOINT`
  );
  console.log(`   Headers:`, JSON.stringify(req.headers, null, 2));
  if (req.body && Object.keys(req.body).length > 0) {
    console.log(`   Body:`, JSON.stringify(req.body, null, 2));
  }
  next();
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error("❌ Server error:", err);
  res.status(500).json({ error: "Internal server error" });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: "Endpoint not found" });
});
