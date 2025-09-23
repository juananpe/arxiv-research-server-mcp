import { config } from "dotenv";
import { McpServer, ResourceTemplate } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { z } from "zod";
import express from "express";
import { randomUUID, createHash } from "crypto";
import jwt from "jsonwebtoken";
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
  async ({ topic, max_results }, { authInfo }) => {
    console.info(
      `>>> 🛠️ Tool: 'search_papers' called for '${topic}' by user: ${
        authInfo?.userId || "anonymous"
      }`
    );

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
  async ({ paper_id }, { authInfo }) => {
    console.info(
      `>>> 🛠️ Tool: 'extract_info' called for '${paper_id}' by user: ${
        authInfo?.userId || "anonymous"
      }`
    );

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
      contents: [{
        uri: uri.href,
        text: content
      }]
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
        contents: [{
          uri: uri.href,
          text: content
        }]
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
        contents: [{
          uri: uri.href,
          text: content
        }]
      };
    } catch (error) {
      const content = `# Error reading papers data for ${topic}\n\nThe papers data file is corrupted.`;
      return {
        contents: [{
          uri: uri.href,
          text: content
        }]
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
          text: `Search for ${num_papers} academic papers about '${topic}' using the search_papers tool. 

Follow these instructions:
1. First, search for papers using search_papers(topic='${topic}', max_results=${num_papers})
2. For each paper found, extract and organize the following information:
   - Paper title
   - Authors
   - Publication date
   - Brief summary of the key findings
   - Main contributions or innovations
   - Methodologies used
   - Relevance to the topic '${topic}'

3. Provide a comprehensive summary that includes:
   - Overview of the current state of research in '${topic}'
   - Common themes and trends across the papers
   - Key research gaps or areas for future investigation
   - Most impactful or influential papers in this area

4. Organize your findings in a clear, structured format with headings and bullet points for easy readability.

Please present both detailed information about each paper and a high-level synthesis of the research landscape in ${topic}.`,
        },
      },
    ],
  })
);

// OAuth Configuration
const OAUTH_CONFIG = {
  clientId: process.env.OAUTH_CLIENT_ID || "arxiv-research-mcp-client",
  clientSecret: process.env.OAUTH_CLIENT_SECRET || "your-client-secret",
  allowedRedirectUris: process.env.ALLOWED_REDIRECT_URIS
    ? process.env.ALLOWED_REDIRECT_URIS.split(",").map((uri) => uri.trim())
    : [
        process.env.OAUTH_REDIRECT_URI || "http://localhost:3004/callback",
        "http://localhost:6274/oauth/callback",
        "http://localhost:6274/oauth/callback/debug",
      ],
  authorizationUrl:
    process.env.AUTHORIZATION_URL || "http://localhost:3004/authorize",
  tokenUrl: process.env.TOKEN_URL || "http://localhost:3004/token",
  scopes: ["read_papers", "search_papers"],
  jwtSecret: process.env.JWT_SECRET || "your-jwt-secret-key",
};

// In-memory storage for OAuth flows (use database in production)
const authorizationCodes = new Map();
const accessTokens = new Map();
const refreshTokens = new Map();

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

// OAuth Helper Functions
function generateAuthorizationCode() {
  return randomUUID();
}

function generateAccessToken(userId, scopes) {
  return jwt.sign(
    {
      sub: userId,
      scopes: scopes,
      type: "access_token",
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 60 * 60, // 1 hour
    },
    OAUTH_CONFIG.jwtSecret
  );
}

function generateRefreshToken(userId) {
  return jwt.sign(
    {
      sub: userId,
      type: "refresh_token",
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 30 * 24 * 60 * 60, // 30 days
    },
    OAUTH_CONFIG.jwtSecret
  );
}

function verifyAccessToken(token) {
  try {
    const decoded = jwt.verify(token, OAUTH_CONFIG.jwtSecret);
    if (decoded.type !== "access_token") {
      throw new Error("Invalid token type");
    }
    return decoded;
  } catch (error) {
    return null;
  }
}

// Authentication Middleware
function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1]; // Bearer TOKEN

  if (!token) {
    return res.status(401).json({ error: "Access token required" });
  }

  const decoded = verifyAccessToken(token);
  if (!decoded) {
    return res.status(403).json({ error: "Invalid or expired token" });
  }

  req.user = {
    id: decoded.sub,
    scopes: decoded.scopes,
  };
  next();
}

// OAuth Discovery Endpoints

// OAuth Authorization Server Metadata (RFC 8414)
app.get("/.well-known/oauth-authorization-server", (req, res) => {
  console.log(`📋 GET /.well-known/oauth-authorization-server from ${req.ip}`);
  const base = getBaseUrl(req);
  res.json({
    issuer: base,
    authorization_endpoint: `${base}/authorize`,
    token_endpoint: `${base}/token`,
    jwks_uri: `${base}/.well-known/jwks.json`,
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code", "refresh_token"],
    code_challenge_methods_supported: ["S256"],
    scopes_supported: OAUTH_CONFIG.scopes,
    token_endpoint_auth_methods_supported: ["client_secret_post"],
    subject_types_supported: ["public"],
  });
});

// OAuth Protected Resource Metadata (RFC 8707)
app.get("/.well-known/oauth-protected-resource", (req, res) => {
  console.log(`📋 GET /.well-known/oauth-protected-resource from ${req.ip}`);
  const base = getBaseUrl(req);
  res.json({
    resource: base,
    authorization_servers: [base],
    scopes_supported: OAUTH_CONFIG.scopes,
    bearer_methods_supported: ["header"],
    resource_documentation: `${base}/`,
  });
});

// MCP-specific OAuth Protected Resource endpoint
app.get("/.well-known/oauth-protected-resource/mcp", (req, res) => {
  console.log(
    `📋 GET /.well-known/oauth-protected-resource/mcp from ${req.ip}`
  );
  const base = getBaseUrl(req);
  res.json({
    resource: `${base}/mcp`,
    authorization_servers: [base],
    scopes_supported: OAUTH_CONFIG.scopes,
    scopes_required: OAUTH_CONFIG.scopes,
    bearer_methods_supported: ["header"],
    resource_documentation: `${base}/`,
    mcp_capabilities: {
      tools: ["search_papers", "extract_info"],
      resources: ["papers://folders", "papers://{topic}"],
      prompts: ["generate_search_prompt"],
      protocol_version: "2024-11-05",
    },
  });
});

// OpenID Configuration (for compatibility)
app.get("/.well-known/openid_configuration", (req, res) => {
  console.log(`📋 GET /.well-known/openid_configuration from ${req.ip}`);
  const base = getBaseUrl(req);
  res.json({
    issuer: base,
    authorization_endpoint: `${base}/authorize`,
    token_endpoint: `${base}/token`,
    userinfo_endpoint: `${base}/tokeninfo`,
    jwks_uri: `${base}/.well-known/jwks.json`,
    response_types_supported: ["code"],
    subject_types_supported: ["public"],
    id_token_signing_alg_values_supported: ["HS256"],
    scopes_supported: [...OAUTH_CONFIG.scopes, "openid"],
    token_endpoint_auth_methods_supported: ["client_secret_post"],
    code_challenge_methods_supported: ["S256"],
  });
});

// JWKS endpoint (placeholder - in production, use proper key management)
app.get("/.well-known/jwks.json", (req, res) => {
  console.log(`📋 GET /.well-known/jwks.json from ${req.ip}`);
  res.json({
    keys: [
      {
        kty: "oct",
        use: "sig",
        kid: "mcp-server-key",
        alg: "HS256",
        // Note: In production, never expose the actual secret
        // This is just for demo purposes
      },
    ],
  });
});

// OAuth Authorization Endpoint
app.get("/authorize", (req, res) => {
  console.log(`🔐 GET /authorize from ${req.ip} with params:`, req.query);
  const {
    client_id,
    redirect_uri,
    response_type,
    scope,
    state,
    code_challenge,
    code_challenge_method,
  } = req.query;

  console.log("🔐 Authorization request received:", req.query);

  // Validate required parameters
  if (!client_id || !redirect_uri || response_type !== "code") {
    return res.status(400).json({
      error: "invalid_request",
      error_description: "Missing or invalid required parameters",
    });
  }

  // Validate client_id
  if (client_id !== OAUTH_CONFIG.clientId) {
    return res.status(400).json({
      error: "invalid_client",
      error_description: "Invalid client_id",
    });
  }

  // Validate redirect_uri against allowed list
  if (!OAUTH_CONFIG.allowedRedirectUris.includes(redirect_uri)) {
    return res.status(400).json({
      error: "invalid_request",
      error_description: `Invalid redirect_uri. Allowed URIs: ${OAUTH_CONFIG.allowedRedirectUris.join(
        ", "
      )}`,
    });
  }

  // In a real implementation, you would show a login/consent screen
  // For this demo, we'll auto-approve
  const authCode = generateAuthorizationCode();
  const userId = "demo-user-" + randomUUID(); // In real app, get from authenticated user

  // Store authorization code with PKCE details
  authorizationCodes.set(authCode, {
    clientId: client_id,
    redirectUri: redirect_uri,
    scope: scope || OAUTH_CONFIG.scopes.join(" "),
    userId: userId,
    codeChallenge: code_challenge,
    codeChallengeMethod: code_challenge_method,
    expiresAt: Date.now() + 10 * 60 * 1000, // 10 minutes
  });

  console.log(
    `✅ Generated authorization code: ${authCode} for user: ${userId}`
  );

  // Redirect back to client with authorization code
  const redirectUrl = new URL(redirect_uri);
  redirectUrl.searchParams.set("code", authCode);
  if (state) {
    redirectUrl.searchParams.set("state", state);
  }

  res.redirect(redirectUrl.toString());
});

// OAuth Token Endpoint
app.post("/token", (req, res) => {
  console.log(
    `🎫 POST /token from ${req.ip} with grant_type:`,
    req.body?.grant_type
  );
  const {
    grant_type,
    code,
    redirect_uri,
    client_id,
    client_secret,
    code_verifier,
    refresh_token,
  } = req.body;

  console.log("🎫 Token request received:", { grant_type, code, client_id });

  if (grant_type === "authorization_code") {
    // Validate required parameters
    if (!code || !redirect_uri || !client_id) {
      return res.status(400).json({
        error: "invalid_request",
        error_description: "Missing required parameters",
      });
    }

    // Validate client_id
    if (client_id !== OAUTH_CONFIG.clientId) {
      return res.status(400).json({
        error: "invalid_client",
        error_description: "Invalid client_id",
      });
    }

    // Retrieve and validate authorization code first to check PKCE
    const authData = authorizationCodes.get(code);
    if (!authData) {
      return res.status(400).json({
        error: "invalid_grant",
        error_description: "Invalid or expired authorization code",
      });
    }

    // For PKCE flows (public clients), client_secret is optional
    // For non-PKCE flows (confidential clients), client_secret is required
    if (!authData.codeChallenge) {
      // Non-PKCE flow - require client_secret
      if (client_secret !== OAUTH_CONFIG.clientSecret) {
        return res.status(400).json({
          error: "invalid_client",
          error_description:
            "Invalid client credentials - client_secret required for non-PKCE flows",
        });
      }
    } else {
      // PKCE flow - client_secret is optional but if provided, must be correct
      if (client_secret && client_secret !== OAUTH_CONFIG.clientSecret) {
        return res.status(400).json({
          error: "invalid_client",
          error_description: "Invalid client_secret",
        });
      }
    }

    // Check if code has expired
    if (Date.now() > authData.expiresAt) {
      authorizationCodes.delete(code);
      return res.status(400).json({
        error: "invalid_grant",
        error_description: "Authorization code has expired",
      });
    }

    // Validate redirect_uri matches
    if (redirect_uri !== authData.redirectUri) {
      return res.status(400).json({
        error: "invalid_grant",
        error_description: "Redirect URI mismatch",
      });
    }

    // Validate PKCE if used
    if (authData.codeChallenge) {
      if (!code_verifier) {
        return res.status(400).json({
          error: "invalid_request",
          error_description: "Code verifier required",
        });
      }

      const hash = createHash("sha256")
        .update(code_verifier)
        .digest("base64url");
      if (hash !== authData.codeChallenge) {
        return res.status(400).json({
          error: "invalid_grant",
          error_description: "Invalid code verifier",
        });
      }
    }

    // Generate tokens
    const scopes = authData.scope.split(" ");
    const accessToken = generateAccessToken(authData.userId, scopes);
    const refreshToken = generateRefreshToken(authData.userId);

    // Store tokens
    accessTokens.set(accessToken, {
      userId: authData.userId,
      scopes: scopes,
      expiresAt: Date.now() + 60 * 60 * 1000, // 1 hour
    });

    refreshTokens.set(refreshToken, {
      userId: authData.userId,
      expiresAt: Date.now() + 30 * 24 * 60 * 60 * 1000, // 30 days
    });

    // Clean up authorization code (one-time use)
    authorizationCodes.delete(code);

    console.log(`✅ Generated access token for user: ${authData.userId}`);

    res.json({
      access_token: accessToken,
      token_type: "Bearer",
      expires_in: 3600, // 1 hour
      refresh_token: refreshToken,
      scope: authData.scope,
    });
  } else if (grant_type === "refresh_token") {
    // Handle refresh token
    if (!refresh_token) {
      return res.status(400).json({
        error: "invalid_request",
        error_description: "Missing refresh token",
      });
    }

    const refreshData = refreshTokens.get(refresh_token);
    if (!refreshData || Date.now() > refreshData.expiresAt) {
      return res.status(400).json({
        error: "invalid_grant",
        error_description: "Invalid or expired refresh token",
      });
    }

    // Generate new access token
    const accessToken = generateAccessToken(
      refreshData.userId,
      OAUTH_CONFIG.scopes
    );
    accessTokens.set(accessToken, {
      userId: refreshData.userId,
      scopes: OAUTH_CONFIG.scopes,
      expiresAt: Date.now() + 60 * 60 * 1000, // 1 hour
    });

    res.json({
      access_token: accessToken,
      token_type: "Bearer",
      expires_in: 3600,
      scope: OAUTH_CONFIG.scopes.join(" "),
    });
  } else {
    res.status(400).json({
      error: "unsupported_grant_type",
      error_description: "Grant type not supported",
    });
  }
});

// OAuth Callback Endpoint (for demo purposes)
app.get("/callback", (req, res) => {
  console.log(`🔄 GET /callback from ${req.ip} with params:`, req.query);
  const { code, state, error } = req.query;

  if (error) {
    return res.status(400).json({
      error: error,
      error_description: "Authorization failed",
    });
  }

  res.json({
    message: "Authorization successful",
    authorization_code: code,
    state: state,
    next_step: "Exchange this code for an access token at /token endpoint",
  });
});

// Token Info Endpoint (for debugging)
app.get("/tokeninfo", authenticateToken, (req, res) => {
  console.log(`🔍 GET /tokeninfo from ${req.ip} for user: ${req.user?.id}`);
  res.json({
    user_id: req.user.id,
    scopes: req.user.scopes,
    client_id: OAUTH_CONFIG.clientId,
  });
});

// Protected MCP endpoint - now uses single server instance
app.post("/mcp", authenticateToken, async (req, res) => {
  console.log(
    `📨 POST /mcp from ${req.ip} - Method: ${req.body?.method}, Session: ${req.headers["mcp-session-id"]}`
  );
  console.log("📨 Received MCP request:", req.body);

  try {
    const body = req.body;
    const rpcId = body && body.id !== undefined ? body.id : null;

    const headerVal = req.headers["mcp-session-id"];
    const clientSessionId = Array.isArray(headerVal) ? headerVal[0] : headerVal;
    const isInit = body && body.method === "initialize";
    let sessionId = clientSessionId;

    if (isInit || !sessionId) {
      sessionId = randomUUID();
    }

    res.setHeader("Mcp-Session-Id", sessionId);

    const transport = await getOrCreateTransport(sessionId);

    // Attach auth info to request for MCP SDK to use
    req.auth = {
      userId: req.user.id,
      scopes: req.user.scopes,
    };

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

// Handle GET requests for SSE streams - now requires authentication
app.get("/mcp", authenticateToken, async (req, res) => {
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

  // Attach auth info to request for MCP SDK to use
  req.authInfo = {
    userId: req.user.id,
    scopes: req.user.scopes,
  };

  await transport.handleRequest(req, res);
});

// Handle DELETE requests for session termination - now requires authentication
app.delete("/mcp", authenticateToken, async (req, res) => {
  console.log(
    `🗑️ DELETE /mcp from ${req.ip} - Session: ${req.headers["mcp-session-id"]}`
  );
  const headerVal = req.headers["mcp-session-id"];
  const sessionId = Array.isArray(headerVal) ? headerVal[0] : headerVal;

  if (sessionId && transports.has(sessionId)) {
    console.log(`🗑️ Cleaning up session: ${sessionId}`);
    transports.delete(sessionId);
    res.status(204).end();
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
    name: "ArXiv Research Server MCP",
    version: "1.0.0",
    description: "MCP server for searching and managing arXiv papers",
    endpoints: {
      mcp: `${base}/mcp`,
      health: `${base}/health`,
      authorize: `${base}/authorize`,
      token: `${base}/token`,
      callback: `${base}/callback`,
      tokeninfo: `${base}/tokeninfo`,
    },
    oauth: {
      authorization_url: `${base}/authorize`,
      token_url: `${base}/token`,
      client_id: OAUTH_CONFIG.clientId,
      scopes: OAUTH_CONFIG.scopes,
    },
    tools: ["search_papers", "extract_info"],
    resources: ["papers://folders", "papers://{topic}"],
    prompts: ["generate_search_prompt"],
    activeSessions: transports.size,
  });
});

// Main function to start the server
async function main() {
  try {
    const port = process.env.PORT || 3004;

    app.listen(port, () => {
      console.log(`🚀 MCP server (Streamable HTTP) started on port ${port}`);
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
});

process.on("SIGTERM", async () => {
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
