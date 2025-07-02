# Google Analytics MCP Server

A professional **Model Context Protocol (MCP) server** that provides secure, standardized access to Google Analytics 4 (GA4) data for AI agents and language models. Built with TypeScript and designed for enterprise-grade reliability and security.

## Overview

This MCP server acts as a bridge between the Model Context Protocol ecosystem and Google Analytics, enabling AI agents to retrieve web analytics data through a secure, well-structured interface. It leverages the Google Analytics Data API to provide comprehensive insights into website performance, user behavior, and engagement metrics.

## Features

- **Comprehensive Analytics Access**: Retrieve page views, active users, events, and user behavior metrics
- **Flexible Date Ranges**: Query data for any time period with customizable date ranges
- **Secure Authentication**: JWT-based authentication with Auth0 integration support
- **Modular Architecture**: Clean, maintainable codebase with clear separation of concerns
- **Enterprise Ready**: Built-in logging, error handling, and configuration management
- **Type Safety**: Full TypeScript implementation with Zod schema validation

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

## Getting Started

### 1. Google Cloud Setup

1. Create a Google Cloud project
2. Enable the Google Analytics Data API
3. Create a service account and download the credentials JSON file
4. Grant the service account "Viewer" access to your GA4 property

### 2. Installation

Clone the repository and install dependencies:

```bash
git clone https://github.com/your-org/mcp-server-google-analytics.git
cd mcp-server-google-analytics
pnpm install
```

### 3. Configuration

Create a `.env` file or set the following environment variables:

#### Required Variables

```bash
# Google Analytics Configuration
GOOGLE_CLIENT_EMAIL="your-service-account@project.iam.gserviceaccount.com"
GOOGLE_PRIVATE_KEY="-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----\n"
GA_PROPERTY_ID="123456789"
GOOGLE_PROJECT_ID="your-google-cloud-project-id"
```

#### Optional Authentication Variables

```bash
# Auth0 JWT Authentication (Optional)
AUTH0_DOMAIN="your-domain.auth0.com"
AUTH0_AUDIENCE="your-api-audience"
MCP_SERVER_RESOURCE="required-resource-indicator"
```

#### Other Configuration

```bash
# Logging
LOG_LEVEL="info"  # Options: error, warn, info, debug
```

### 4. Usage

#### Starting the Server

```bash
npm start
# or
pnpm start
# or
yarn start
```

#### Development Mode

```bash
npm run dev
# or
pnpm dev
# or
yarn dev
```

#### Claude Desktop Configuration

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

## Production Deployment with Docker

This repository includes a production-optimized Docker setup with both Docker Compose and standalone Docker options for containerized deployment.

### Recommended: Using Docker Compose

The `docker-compose.yml` file simplifies deployment by automatically handling container configuration, port mapping, and environment variable loading.

```bash
docker compose up --build
```

This command will:

- Build the Docker image using the multi-stage Dockerfile
- Create and start the container with the name `mcp-server-google-analytics`
- Automatically load environment variables from your `.env` file
- Expose the server on port 8080

To run in detached mode:

```bash
docker compose up --build -d
```

To stop the service:

```bash
docker compose down
```

### Alternative: Manual Docker Commands

If you prefer to use Docker commands directly:

#### Building the Docker Image

```bash
docker build -t mcp-server-google-analytics .
```

#### Running the Docker Container

```bash
docker run --env-file ./.env -p 8080:8080 mcp-server-google-analytics
```

The container will automatically load environment variables from your `.env` file and expose the server on port 8080.

## Available Tools

The server exposes four powerful tools for accessing Google Analytics data:

### `get_page_views`

Retrieves page view metrics with optional dimension breakdowns.

**Parameters:**

- `startDate` (string): Start date in YYYY-MM-DD format
- `endDate` (string): End date in YYYY-MM-DD format
- `dimensions` (array, optional): Additional dimensions like `["page", "country"]`

**Example:**

```json
{
  "startDate": "2024-01-01",
  "endDate": "2024-01-31",
  "dimensions": ["page", "country"]
}
```

### `get_active_users`

Retrieves active user metrics for the specified date range.

**Parameters:**

- `startDate` (string): Start date in YYYY-MM-DD format
- `endDate` (string): End date in YYYY-MM-DD format

**Example:**

```json
{
  "startDate": "2024-01-01",
  "endDate": "2024-01-31"
}
```

### `get_events`

Retrieves event data and metrics, optionally filtered by event name.

**Parameters:**

- `startDate` (string): Start date in YYYY-MM-DD format
- `endDate` (string): End date in YYYY-MM-DD format
- `eventName` (string, optional): Specific event name to filter by

**Example:**

```json
{
  "startDate": "2024-01-01",
  "endDate": "2024-01-31",
  "eventName": "purchase"
}
```

### `get_user_behavior`

Retrieves user behavior and engagement metrics including session duration and bounce rate.

**Parameters:**

- `startDate` (string): Start date in YYYY-MM-DD format
- `endDate` (string): End date in YYYY-MM-DD format

**Example:**

```json
{
  "startDate": "2024-01-01",
  "endDate": "2024-01-31"
}
```

## Available Scripts

The following npm scripts are available for development and deployment:

- **`npm run build`**: Compile TypeScript to JavaScript
- **`npm start`**: Run the compiled server
- **`npm run dev`**: Run in development mode with auto-reload
- **`npm test`**: Run the test suite with Jest
- **`npm run lint`**: Lint TypeScript files with ESLint

## Security Considerations

- **Environment Variables**: Always use environment variables for sensitive credentials
- **Service Account Permissions**: Follow the principle of least privilege
- **JWT Authentication**: Enable JWT authentication for production deployments
- **API Rate Limits**: Monitor Google Analytics API usage and implement rate limiting
- **Credential Rotation**: Regularly rotate service account credentials
- **CORS Configuration**: Implement appropriate CORS settings for web deployments

## Dependencies

### Core Dependencies

- **`@google-analytics/data`**: Official Google Analytics Data API client
- **`@modelcontextprotocol/sdk`**: MCP SDK for building MCP servers
- **`express`**: Web framework for Node.js
- **`express-oauth2-jwt-bearer`**: JWT authentication middleware
- **`googleapis`**: Google APIs Node.js client library
- **`winston`**: Professional logging library
- **`zod`**: TypeScript-first schema validation

### Development Dependencies

- **TypeScript**: Type-safe JavaScript development
- **Jest**: Testing framework
- **ESLint**: Code linting and style enforcement

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

For issues, questions, or contributions, please visit our [GitHub repository](https://github.com/your-org/mcp-server-google-analytics) or open an issue.
