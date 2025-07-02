# MCP Server for Google Analytics

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Node.js Version](https://img.shields.io/badge/node-%3E%3D20.0.0-brightgreen)](https://nodejs.org/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.0+-blue)](https://www.typescriptlang.org/)
[![Docker](https://img.shields.io/badge/Docker-supported-blue)](https://www.docker.com/)

A production-ready **Model Context Protocol (MCP) server** that provides secure, standardized access to Google Analytics 4 (GA4) data for AI agents and language models. Built with TypeScript and designed for enterprise-grade reliability and security.

## Features

- **Comprehensive Analytics Access**: Retrieve page views, active users, events, and user behavior metrics
- **HTTP Transport**: Full HTTP-based MCP implementation with session management
- **Flexible Authentication**: Configurable authentication modes (none/JWT/OAuth 2.1)
- **Enterprise Security**: OAuth 2.1 compliant authentication with Auth0 integration
- **Docker Ready**: Production-optimized containerization with multi-stage builds
- **Type Safety**: Full TypeScript implementation with Zod schema validation
- **Modular Architecture**: Clean, maintainable codebase with clear separation of concerns

## Architecture

The server follows a modular architecture with clear separation of concerns:

```
src/
├── index.ts              # Application entry point
├── config/               # Configuration management
│   └── index.ts         # Environment variable loading and validation
├── lib/                 # Core application logic
│   └── server.ts        # MCP server implementation and tool definitions
├── middleware/          # Authentication middleware
│   └── auth.ts          # JWT-based authentication with Auth0
├── schemas/             # Data validation schemas
│   └── index.ts         # Zod schemas for input validation
└── utils/               # Utility functions
    ├── index.ts         # Helper functions for validation and formatting
    └── logger.ts        # Winston logger configuration
```

## Prerequisites

- **Node.js**: Version 20 or higher
- **Google Analytics 4**: Active GA4 property
- **Google Cloud Project**: With Analytics Data API enabled
- **Service Account**: With appropriate GA4 permissions
- **Auth0 Account**: (Optional) For JWT authentication

## Google Cloud Authentication

### Authentication Architecture

This MCP server implements two distinct authentication layers:

1. **MCP Transport Authentication** (Optional): Controls access between MCP clients and this server
   - Configured via `MCP_AUTH_MODE` (none/jwt/oauth)
   - When set to `none`, no client authentication is required
   
2. **Google Analytics API Authentication** (Required): Controls access from this server to Google Analytics
   - Always required regardless of MCP authentication mode
   - Uses Google Cloud service account credentials
   - Cannot be bypassed or disabled

### Required Google Cloud Console Setup

Even with `MCP_AUTH_MODE=none`, you must configure Google Cloud Console for Google Analytics API access.

#### Step 1: Create Google Cloud Project

1. Navigate to [Google Cloud Console](https://console.cloud.google.com)
2. Create a new project or select an existing one
3. Note the Project ID for later use

#### Step 2: Enable Required APIs

1. Go to **APIs & Services > Library**
2. Search for and enable:
   - **Google Analytics Data API v1** (required for GA4 data access)
   - **Google Analytics Reporting API** (required for some operations)

#### Step 3: Create Service Account

1. Go to **IAM & Admin > Service Accounts**
2. Click **+ Create Service Account**
3. Enter a descriptive name (e.g., "mcp-analytics-reader")
4. Skip role assignment (roles are managed in Google Analytics)
5. Click **Done**

#### Step 4: Generate Service Account Key

1. Click on the created service account
2. Go to **Keys** tab
3. Click **Add Key > Create new key**
4. Select **JSON** format
5. Download and securely store the JSON file

#### Step 5: Extract Credentials

From the downloaded JSON file, extract these values for your environment:

```json
{
  "client_email": "service-account@project-id.iam.gserviceaccount.com",
  "private_key": "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----\n",
  "project_id": "your-project-id"
}
```

#### Step 6: Grant Analytics Access

1. Open [Google Analytics](https://analytics.google.com)
2. Navigate to **Admin > Property Access Management**
3. Click **+ Add users**
4. Enter the service account email from Step 5
5. Assign **Viewer** role
6. Click **Add**

#### Step 7: Get Property ID

1. In Google Analytics, go to **Admin > Property > Property details**
2. Copy the Property ID (numeric value like `123456789`)
3. Format as `properties/123456789` for configuration

### Common Authentication Misconceptions

**Important**: Setting `MCP_AUTH_MODE=none` only disables authentication between MCP clients and this server. It does not affect the requirement for Google Analytics API authentication, which uses service account credentials and is always mandatory for accessing GA4 data.

### Troubleshooting Authentication

- **403 Forbidden**: Service account lacks proper GA4 property access
- **401 Unauthorized**: Invalid or expired service account credentials
- **API Not Enabled**: Required Google Cloud APIs not activated
- **Invalid Property ID**: Ensure format is `properties/numeric-id`

## Auth0 Setup (Optional - For JWT/OAuth Authentication)

If you plan to use `MCP_AUTH_MODE=jwt` or `MCP_AUTH_MODE=oauth`, you must configure Auth0 for authentication.

### Required Auth0 Configuration

#### Step 1: Create Auth0 Account

1. Navigate to [Auth0](https://auth0.com)
2. Sign up for a free account or log into existing account
3. Create a new tenant (or use existing one)

#### Step 2: Create API Resource

1. In Auth0 Dashboard, go to **Applications > APIs**
2. Click **+ Create API**
3. Enter API details:
   - **Name**: `MCP Google Analytics Server`
   - **Identifier**: `https://mcp.yourdomain.com` (this becomes your `AUTH0_AUDIENCE`)
   - **Signing Algorithm**: `RS256`
4. Click **Create**

#### Step 3: Configure API Settings

1. In your API settings, go to **Settings** tab
2. Note the **Identifier** - this is your `AUTH0_AUDIENCE`
3. Go to **Scopes** tab and add:
   - `read:analytics` - Read access to Google Analytics data
4. Enable **RBAC** and **Add Permissions in the Access Token**

#### Step 4: Create Application (For Testing)

1. Go to **Applications > Applications**
2. Click **+ Create Application**
3. Choose **Machine to Machine Applications**
4. Select your MCP API created in Step 2
5. Grant the `read:analytics` scope
6. Note the **Client ID** and **Client Secret**

#### Step 5: Get Domain Information

1. In Auth0 Dashboard, note your **Domain** (e.g., `your-tenant.auth0.com`)
2. This becomes your `AUTH0_DOMAIN` environment variable

#### Step 6: Configure Environment Variables

```bash
# Auth0 Configuration
AUTH0_DOMAIN=your-tenant.auth0.com
AUTH0_AUDIENCE=https://mcp.yourdomain.com
MCP_SERVER_RESOURCE=https://mcp.yourdomain.com
MCP_RESOURCE_URI=https://mcp.yourdomain.com
```

### Testing Auth0 Configuration

You can test your Auth0 setup by obtaining a token:

```bash
curl -X POST https://your-tenant.auth0.com/oauth/token \
  -H "Content-Type: application/json" \
  -d '{
    "client_id": "your-client-id",
    "client_secret": "your-client-secret",
    "audience": "https://mcp.yourdomain.com",
    "grant_type": "client_credentials"
  }'
```

Use the returned `access_token` to test authenticated requests to your MCP server.

### Common Auth0 Misconceptions

**Important**: Auth0 setup is only required if you want to authenticate MCP clients connecting to your server. If you set `MCP_AUTH_MODE=none`, Auth0 configuration is not needed, but Google Analytics API authentication is still required.

## Quick Start

### 1. Google Cloud Setup

Complete the [Google Cloud Authentication](#google-cloud-authentication) section above before proceeding.

### 2. Installation

```bash
git clone https://github.com/nalyk/mcp-server-google-analytics.git
cd mcp-server-google-analytics
npm install
```

### 3. Configuration

Create a `.env` file from the example:

```bash
cp .env.example .env
```

Configure the required environment variables using the credentials from Google Cloud setup:

```bash
# HTTP Server Configuration
PORT=3001
MCP_AUTH_MODE=none
MCP_HTTP_HOST=0.0.0.0
MCP_CORS_ORIGINS=*
MCP_RESOURCE_URI=https://mcp.yourdomain.com

# Google Analytics Configuration (from Google Cloud setup)
GA_PROPERTY_ID=properties/123456789
GOOGLE_PROJECT_ID=your-google-cloud-project-id
GOOGLE_CLIENT_EMAIL=your-service-account@project.iam.gserviceaccount.com
GOOGLE_PRIVATE_KEY="-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----\n"

# Optional: MCP Transport Authentication
AUTH0_DOMAIN=your-domain.auth0.com
AUTH0_AUDIENCE=your-api-audience
MCP_SERVER_RESOURCE=required-resource-indicator
```

### 4. Development

```bash
# Start in development mode
npm run dev

# Build for production
npm run build

# Start production server
npm start
```

The server will be available at `http://localhost:3001` with the following endpoints:

- **Health Check**: `GET /health`
- **MCP Endpoint**: `POST /mcp` (JSON-RPC 2.0)
- **MCP SSE**: `GET /mcp` (Server-Sent Events)
- **OAuth Metadata**: `GET /.well-known/oauth-protected-resource` (OAuth mode only)

## Docker Deployment

### Using Docker Compose (Recommended)

```bash
# Build and start the service
docker compose up --build

# Run in detached mode
docker compose up --build -d

# Stop the service
docker compose down
```

### Using Docker directly

```bash
# Build the image
docker build -t mcp-server-google-analytics .

# Run the container
docker run --env-file .env -p 3001:3001 mcp-server-google-analytics
```

## Authentication Modes

The server supports three authentication modes via the `MCP_AUTH_MODE` environment variable:

### None (Development)
```bash
MCP_AUTH_MODE=none
```
No authentication required. Suitable for development and trusted environments.

### JWT (Production)
```bash
MCP_AUTH_MODE=jwt
AUTH0_DOMAIN=your-domain.auth0.com
AUTH0_AUDIENCE=your-api-audience
MCP_SERVER_RESOURCE=your-resource-indicator
```
JWT-based authentication using Auth0. Requires valid JWT tokens in request headers.

### OAuth 2.1 (Production)
```bash
MCP_AUTH_MODE=oauth
AUTH0_DOMAIN=your-domain.auth0.com
AUTH0_AUDIENCE=your-api-audience
MCP_RESOURCE_URI=https://mcp.yourdomain.com
MCP_SERVER_RESOURCE=your-resource-indicator
```
Full OAuth 2.1 compliance with protected resource metadata and Auth0 integration. Provides automatic authorization server discovery and resource-bound tokens for maximum security.

## Available Tools

The server exposes four tools for accessing Google Analytics data:

### `get_page_views`

Retrieves page view metrics with optional dimension breakdowns.

**Parameters:**
- `startDate` (string): Start date in YYYY-MM-DD format
- `endDate` (string): End date in YYYY-MM-DD format
- `dimensions` (array, optional): Additional dimensions like `["page", "country"]`

### `get_active_users`

Retrieves active user metrics for the specified date range.

**Parameters:**
- `startDate` (string): Start date in YYYY-MM-DD format
- `endDate` (string): End date in YYYY-MM-DD format

### `get_events`

Retrieves event data and metrics, optionally filtered by event name.

**Parameters:**
- `startDate` (string): Start date in YYYY-MM-DD format
- `endDate` (string): End date in YYYY-MM-DD format
- `eventName` (string, optional): Specific event name to filter by

### `get_user_behavior`

Retrieves user behavior and engagement metrics including session duration and bounce rate.

**Parameters:**
- `startDate` (string): Start date in YYYY-MM-DD format
- `endDate` (string): End date in YYYY-MM-DD format

## Claude Desktop Integration

Add this configuration to your Claude Desktop settings:

```json
{
  "mcpServers": {
    "google-analytics": {
      "command": "node",
      "args": ["path/to/mcp-server-google-analytics/dist/index.js"],
      "env": {
        "GOOGLE_CLIENT_EMAIL": "your-service-account@project.iam.gserviceaccount.com",
        "GOOGLE_PRIVATE_KEY": "your-private-key",
        "GA_PROPERTY_ID": "your-ga4-property-id",
        "GOOGLE_PROJECT_ID": "your-google-cloud-project-id"
      }
    }
  }
}
```

## HTTP Client Integration

For HTTP-based MCP clients, connect to:

```
POST http://localhost:3001/mcp
Content-Type: application/json

{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/list",
  "params": {}
}
```

## Available Scripts

- `npm run build` - Compile TypeScript to JavaScript
- `npm start` - Run the compiled server
- `npm run dev` - Run in development mode with auto-reload
- `npm test` - Run the test suite with Jest
- `npm run lint` - Lint TypeScript files with ESLint

## Security Considerations

- **Environment Variables**: Always use environment variables for sensitive credentials
- **Service Account Permissions**: Follow the principle of least privilege
- **JWT Authentication**: Enable JWT authentication for production deployments
- **API Rate Limits**: Monitor Google Analytics API usage and implement rate limiting
- **Credential Rotation**: Regularly rotate service account credentials
- **CORS Configuration**: Configure appropriate CORS settings for your use case

## Dependencies

### Core Dependencies

- `@google-analytics/data` - Official Google Analytics Data API client
- `@modelcontextprotocol/sdk` - MCP SDK for building MCP servers
- `express` - Web framework for Node.js
- `express-oauth2-jwt-bearer` - JWT authentication middleware
- `googleapis` - Google APIs Node.js client library
- `winston` - Professional logging library
- `zod` - TypeScript-first schema validation

### Development Dependencies

- `typescript` - Type-safe JavaScript development
- `jest` - Testing framework
- `eslint` - Code linting and style enforcement

## Contributing

We welcome contributions! Please follow these steps:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

Please ensure your code follows the existing style and includes appropriate tests.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

For issues, questions, or contributions, please visit our [GitHub repository](https://github.com/nalyk/mcp-server-google-analytics) or open an issue.