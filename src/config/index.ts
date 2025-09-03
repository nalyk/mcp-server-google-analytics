/**
 * Configuration module for the MCP Google Analytics server
 * Loads and validates environment variables
 */

import * as dotenv from 'dotenv';

// Load environment variables from .env file
dotenv.config();

export interface Config {
  server: {
    name: string;
    version: string;
  };
  transport: 'stdio' | 'http';
  http: {
    port: number;
    host: string;
    cors: {
      origins: string[];
      allowedHeaders: string[];
      exposedHeaders: string[];
    };
    sessionMode: 'stateful' | 'stateless';
  };
  auth: {
    mode: 'none' | 'jwt' | 'oauth';
    domain?: string;
    audience?: string;
    requiredResource?: string;
    resourceUri?: string;
  };
  googleAnalytics: {
    clientEmail: string;
    privateKey: string;
    propertyId: string;
    projectId: string;
  };
  oauth?: {
    clientId?: string;
    clientSecret?: string;
    redirectUri?: string;
  };
}

/**
 * Validates that required environment variables are present
 */
function validateRequiredEnvVars(): void {
  const required = [
    'GOOGLE_CLIENT_EMAIL',
    'GOOGLE_PRIVATE_KEY',
    'GA_PROPERTY_ID',
    'GOOGLE_PROJECT_ID'
  ];

  const missing = required.filter(key => !process.env[key]);
  
  if (missing.length > 0) {
    throw new Error(`Missing required environment variables: ${missing.join(', ')}`);
  }
}

/**
 * Parse CORS origins from environment variable
 */
function parseCorsOrigins(origins?: string): string[] {
  if (!origins) return ['*'];
  return origins.split(',').map(origin => origin.trim());
}

/**
 * Loads and exports the application configuration
 */
export function loadConfig(): Config {
  validateRequiredEnvVars();

  const authMode = (process.env.MCP_AUTH_MODE || 'none') as 'none' | 'jwt' | 'oauth';
  const transport = (process.env.MCP_TRANSPORT || 'stdio') as 'stdio' | 'http';

  return {
    server: {
      name: process.env.MCP_SERVER_NAME || 'mcp-server-google-analytics',
      version: process.env.MCP_SERVER_VERSION || '2.0.0',
    },
    transport,
    http: {
      port: parseInt(process.env.PORT || '3000', 10),
      host: process.env.MCP_HTTP_HOST || '0.0.0.0',
      cors: {
        origins: parseCorsOrigins(process.env.MCP_CORS_ORIGINS),
        allowedHeaders: ['Content-Type', 'Authorization', 'mcp-session-id'],
        exposedHeaders: ['mcp-session-id'],
      },
      sessionMode: (process.env.MCP_HTTP_SESSION_MODE || 'stateless') as 'stateful' | 'stateless',
    },
    auth: {
      mode: authMode,
      domain: process.env.AUTH0_DOMAIN,
      audience: process.env.AUTH0_AUDIENCE,
      requiredResource: process.env.MCP_SERVER_RESOURCE,
      resourceUri: process.env.MCP_RESOURCE_URI || `http://${process.env.MCP_HTTP_HOST || '0.0.0.0'}:${process.env.PORT || '3001'}`,
    },
    googleAnalytics: {
      clientEmail: process.env.GOOGLE_CLIENT_EMAIL!,
      privateKey: process.env.GOOGLE_PRIVATE_KEY!.replace(/\\n/g, '\n'),
      propertyId: process.env.GA_PROPERTY_ID!,
      projectId: process.env.GOOGLE_PROJECT_ID!,
    },
    oauth: {
      clientId: process.env.OAUTH_CLIENT_ID,
      clientSecret: process.env.OAUTH_CLIENT_SECRET,
      redirectUri: process.env.OAUTH_REDIRECT_URI,
    },
  };
}

// Export a singleton instance
export const config = loadConfig();
