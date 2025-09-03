#!/usr/bin/env node

/**
 * MCP Google Analytics Server - SDK Implementation with Security Layer
 * Professional implementation using @mcp/sdk with OAuth 2.0 authentication
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import {
  CallToolRequest,
  CallToolRequestSchema,
  ErrorCode,
  ListToolsRequestSchema,
  McpError,
} from '@modelcontextprotocol/sdk/types.js';
import { BetaAnalyticsDataClient } from '@google-analytics/data';
import { z } from 'zod';
import express, { Express, Request, Response } from 'express';
import cors from 'cors';

// Import configuration and schemas
import { config } from '../config';
import {
  GetPageViewsSchema,
  GetActiveUsersSchema,
  GetEventsSchema,
  GetUserBehaviorSchema,
  GetPageViewsInput,
  GetActiveUsersInput,
  GetEventsInput,
  GetUserBehaviorInput
} from '../schemas';
import { validateInput, createSuccessResponse, createError, formatGAResponse } from '../utils';

// Import authentication utilities
import { createAuthMiddlewareFromEnv, getUserFromRequest } from '../middleware/auth';

// Import logger
import logger from '../utils/logger';

/**
 * Authentication configuration interface
 */
interface AuthConfig {
  enabled: boolean;
  domain?: string;
  audience?: string;
  requiredResource?: string;
}

/**
 * Google Analytics MCP Server using the official SDK with Security Layer
 */
class GoogleAnalyticsServer {
  private server: Server;
  private analyticsClient: BetaAnalyticsDataClient;
  private propertyId: string;
  private authConfig: AuthConfig;
  private app: Express;

  constructor() {
    logger.info('Initializing Google Analytics MCP Server');
    
    this.server = new Server(
      {
        name: config.server.name,
        version: config.server.version,
      },
      {
        capabilities: {
          tools: {},
        },
      }
    );

    // Initialize configuration
    this.propertyId = config.googleAnalytics.propertyId;
    logger.debug('Google Analytics Property ID configured', { propertyId: this.propertyId });
    
    // Initialize authentication configuration using new config structure
    this.authConfig = {
      enabled: config.auth.mode !== 'none',
      domain: config.auth.domain,
      audience: config.auth.audience,
      requiredResource: config.auth.requiredResource,
    };

    // Log authentication status
    logger.info('Authentication configuration', {
      mode: config.auth.mode,
      enabled: this.authConfig.enabled,
      domain: this.authConfig.domain,
      audience: this.authConfig.audience,
    });
    
    // Initialize Google Analytics client
    this.analyticsClient = new BetaAnalyticsDataClient({
      credentials: {
        client_email: config.googleAnalytics.clientEmail,
        private_key: config.googleAnalytics.privateKey,
      },
      projectId: config.googleAnalytics.projectId,
    });

    logger.info('Google Analytics client initialized successfully');
    
    // Initialize Express app
    this.app = express();
    this.setupExpress();
    this.setupToolHandlers();
  }

  /**
   * Validate authentication token if authentication is enabled
   */
  private async validateAuthentication(request: any): Promise<void> {
    if (!this.authConfig.enabled) {
      return; // Authentication disabled, skip validation
    }

    // Extract token from request metadata or headers
    const token = this.extractTokenFromRequest(request);
    
    if (!token) {
      throw new McpError(
        ErrorCode.InvalidRequest,
        'Authentication required: Missing access token'
      );
    }

    try {
      // Validate the JWT token using the auth middleware logic
      await this.validateJWTToken(token);
      logger.info('Authentication successful');
    } catch (error) {
      logger.error('Authentication failed', { error: error instanceof Error ? error.message : 'Invalid token' });
      throw new McpError(
        ErrorCode.InvalidRequest,
        `Authentication failed: ${error instanceof Error ? error.message : 'Invalid token'}`
      );
    }
  }

  /**
   * Extract authentication token from MCP request
   */
  private extractTokenFromRequest(request: any): string | null {
    // Check for token in request metadata
    if (request.meta?.authorization) {
      const authHeader = request.meta.authorization;
      if (authHeader.startsWith('Bearer ')) {
        return authHeader.substring(7);
      }
    }

    // Check for token in request params (alternative approach)
    if (request.params?.meta?.token) {
      return request.params.meta.token;
    }

    // Check environment variable as fallback for development
    if (process.env.MCP_ACCESS_TOKEN) {
      return process.env.MCP_ACCESS_TOKEN;
    }

    return null;
  }

  /**
   * Validate JWT token against Auth0
   */
  private async validateJWTToken(token: string): Promise<void> {
    if (!this.authConfig.domain || !this.authConfig.audience) {
      throw new Error('Authentication configuration incomplete');
    }

    // For MCP servers, we'll implement a simplified JWT validation
    // In a production environment, you would use a proper JWT library
    try {
      // Decode JWT payload (simplified validation)
      const payload = this.decodeJWTPayload(token);
      
      // Validate audience
      if (payload.aud !== this.authConfig.audience &&
          (!Array.isArray(payload.aud) || !payload.aud.includes(this.authConfig.audience))) {
        throw new Error('Invalid audience');
      }

      // Validate issuer
      const expectedIssuer = `https://${this.authConfig.domain}/`;
      if (payload.iss !== expectedIssuer) {
        throw new Error('Invalid issuer');
      }

      // Validate expiration
      const now = Math.floor(Date.now() / 1000);
      if (payload.exp && payload.exp < now) {
        throw new Error('Token expired');
      }

      // Validate resource indicator if required
      if (this.authConfig.requiredResource) {
        const tokenResource = payload.resource || payload.aud;
        const hasRequiredResource = Array.isArray(tokenResource)
          ? tokenResource.includes(this.authConfig.requiredResource)
          : tokenResource === this.authConfig.requiredResource;

        if (!hasRequiredResource) {
          throw new Error(`Missing required resource: ${this.authConfig.requiredResource}`);
        }
      }

      logger.info('JWT validation successful', { userId: payload.sub, audience: payload.aud });
    } catch (error) {
      throw new Error(`JWT validation failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  /**
   * Decode JWT payload (simplified implementation)
   * Note: In production, use a proper JWT library with signature verification
   */
  private decodeJWTPayload(token: string): any {
    try {
      const parts = token.split('.');
      if (parts.length !== 3) {
        throw new Error('Invalid JWT format');
      }

      const payload = parts[1];
      const decoded = Buffer.from(payload, 'base64url').toString('utf8');
      return JSON.parse(decoded);
    } catch (error) {
      throw new Error('Failed to decode JWT payload');
    }
  }

  /**
   * Set up tool handlers using the SDK pattern
   */
  private setupToolHandlers(): void {
    // Page Views tool
    this.server.setRequestHandler(ListToolsRequestSchema, async () => {
      return {
        tools: [
          {
            name: 'get_page_views',
            description: 'Get page view data from Google Analytics',
            inputSchema: {
              type: 'object',
              properties: {
                startDate: {
                  type: 'string',
                  description: 'Start date in YYYY-MM-DD format',
                },
                endDate: {
                  type: 'string',
                  description: 'End date in YYYY-MM-DD format',
                },
                dimensions: {
                  type: 'array',
                  items: { type: 'string' },
                  description: 'Dimensions to group by (e.g., pagePath, pageTitle)',
                  default: ['pagePath'],
                },
                limit: {
                  type: 'number',
                  description: 'Maximum number of results to return',
                  default: 10,
                },
              },
              required: ['startDate', 'endDate'],
            },
          },
          {
            name: 'get_active_users',
            description: 'Get active user data from Google Analytics',
            inputSchema: {
              type: 'object',
              properties: {
                startDate: {
                  type: 'string',
                  description: 'Start date in YYYY-MM-DD format',
                },
                endDate: {
                  type: 'string',
                  description: 'End date in YYYY-MM-DD format',
                },
                dimensions: {
                  type: 'array',
                  items: { type: 'string' },
                  description: 'Dimensions to group by (e.g., country, city, deviceCategory)',
                  default: ['country'],
                },
                limit: {
                  type: 'number',
                  description: 'Maximum number of results to return',
                  default: 10,
                },
              },
              required: ['startDate', 'endDate'],
            },
          },
          {
            name: 'get_events',
            description: 'Get event data from Google Analytics',
            inputSchema: {
              type: 'object',
              properties: {
                startDate: {
                  type: 'string',
                  description: 'Start date in YYYY-MM-DD format',
                },
                endDate: {
                  type: 'string',
                  description: 'End date in YYYY-MM-DD format',
                },
                eventName: {
                  type: 'string',
                  description: 'Specific event name to filter by (optional)',
                },
                dimensions: {
                  type: 'array',
                  items: { type: 'string' },
                  description: 'Dimensions to group by (e.g., eventName, pagePath)',
                  default: ['eventName'],
                },
                limit: {
                  type: 'number',
                  description: 'Maximum number of results to return',
                  default: 10,
                },
              },
              required: ['startDate', 'endDate'],
            },
          },
          {
            name: 'get_user_behavior',
            description: 'Get user behavior and engagement metrics from Google Analytics',
            inputSchema: {
              type: 'object',
              properties: {
                startDate: {
                  type: 'string',
                  description: 'Start date in YYYY-MM-DD format',
                },
                endDate: {
                  type: 'string',
                  description: 'End date in YYYY-MM-DD format',
                },
                dimensions: {
                  type: 'array',
                  items: { type: 'string' },
                  description: 'Dimensions to group by (e.g., pagePath, deviceCategory)',
                  default: ['pagePath'],
                },
                limit: {
                  type: 'number',
                  description: 'Maximum number of results to return',
                  default: 10,
                },
              },
              required: ['startDate', 'endDate'],
            },
          },
        ],
      };
    });

    // Tool call handler
    this.server.setRequestHandler(CallToolRequestSchema, async (request: CallToolRequest) => {
      const { name, arguments: args } = request.params;

      logger.info('Incoming tool request', { toolName: name, args });

      try {
        // Validate authentication before processing any tool calls
        await this.validateAuthentication(request);

        switch (name) {
          case 'get_page_views': {
            const validatedArgs = validateInput(GetPageViewsSchema, args) as GetPageViewsInput;
            const result = await this.handlePageViews(validatedArgs);
            return {
              content: [
                {
                  type: 'text',
                  text: JSON.stringify(result, null, 2),
                },
              ],
            };
          }

          case 'get_active_users': {
            const validatedArgs = validateInput(GetActiveUsersSchema, args) as GetActiveUsersInput;
            const result = await this.handleActiveUsers(validatedArgs);
            return {
              content: [
                {
                  type: 'text',
                  text: JSON.stringify(result, null, 2),
                },
              ],
            };
          }

          case 'get_events': {
            const validatedArgs = validateInput(GetEventsSchema, args) as GetEventsInput;
            const result = await this.handleEvents(validatedArgs);
            return {
              content: [
                {
                  type: 'text',
                  text: JSON.stringify(result, null, 2),
                },
              ],
            };
          }

          case 'get_user_behavior': {
            const validatedArgs = validateInput(GetUserBehaviorSchema, args) as GetUserBehaviorInput;
            const result = await this.handleUserBehavior(validatedArgs);
            return {
              content: [
                {
                  type: 'text',
                  text: JSON.stringify(result, null, 2),
                },
              ],
            };
          }

          default:
            throw new McpError(
              ErrorCode.MethodNotFound,
              `Unknown tool: ${name}`
            );
        }
      } catch (error) {
        if (error instanceof z.ZodError) {
          logger.error('Tool validation error', { toolName: name, error: error.message });
          throw new McpError(
            ErrorCode.InvalidParams,
            `Invalid arguments: ${error.message}`
          );
        }
        
        if (error instanceof McpError) {
          logger.error('MCP error in tool execution', { toolName: name, error: error.message });
          throw error;
        }

        const errorMessage = error instanceof Error ? error.message : 'Unknown error';
        logger.error('Tool execution failed', { toolName: name, error: errorMessage });
        throw new McpError(
          ErrorCode.InternalError,
          `Tool execution failed: ${errorMessage}`
        );
      }
    });
  }

  /**
   * Handle page views data retrieval
   */
  private async handlePageViews(args: GetPageViewsInput): Promise<any> {
    try {
      const dimensions = args.dimensions;
      
      const request = {
        property: `properties/${this.propertyId}`,
        dateRanges: [
          {
            startDate: args.startDate,
            endDate: args.endDate,
          },
        ],
        dimensions: dimensions.map(name => ({ name })),
        metrics: [
          { name: 'screenPageViews' },
          { name: 'sessions' },
          { name: 'bounceRate' },
          { name: 'averageSessionDuration' },
        ],
        orderBys: [
          {
            metric: { metricName: 'screenPageViews' },
            desc: true,
          },
        ],
        limit: args.limit,
      };

      const [response] = await this.analyticsClient.runReport(request);
      const formattedResponse = formatGAResponse(response);
      
      return createSuccessResponse(formattedResponse, {
        dateRange: {
          startDate: args.startDate,
          endDate: args.endDate,
        },
        dimensions: dimensions,
        totalRows: formattedResponse.metadata?.rowCount || 0,
      });
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error occurred';
      logger.error('Page Views tool error', { error: errorMessage, args });
      throw new McpError(
        ErrorCode.InternalError,
        `Google Analytics API request failed: ${errorMessage}`
      );
    }
  }

  /**
   * Handle active users data retrieval
   */
  private async handleActiveUsers(args: GetActiveUsersInput): Promise<any> {
    try {
      const request = {
        property: `properties/${this.propertyId}`,
        dateRanges: [
          {
            startDate: args.startDate,
            endDate: args.endDate,
          },
        ],
        dimensions: args.dimensions.map(name => ({ name })),
        metrics: [
          { name: 'activeUsers' },
          { name: 'newUsers' },
          { name: 'sessions' },
        ],
        orderBys: [
          {
            metric: { metricName: 'activeUsers' },
            desc: true,
          },
        ],
        limit: args.limit,
      };

      const [response] = await this.analyticsClient.runReport(request);
      const formattedResponse = formatGAResponse(response);
      
      return createSuccessResponse(formattedResponse, {
        dateRange: {
          startDate: args.startDate,
          endDate: args.endDate,
        },
        dimensions: args.dimensions,
        totalRows: formattedResponse.metadata?.rowCount || 0,
      });
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error occurred';
      logger.error('Active Users tool error', { error: errorMessage, args });
      throw new McpError(
        ErrorCode.InternalError,
        `Google Analytics API request failed: ${errorMessage}`
      );
    }
  }

  /**
   * Handle events data retrieval
   */
  private async handleEvents(args: GetEventsInput): Promise<any> {
    try {
      const request = {
        property: `properties/${this.propertyId}`,
        dateRanges: [
          {
            startDate: args.startDate,
            endDate: args.endDate,
          },
        ],
        dimensions: args.dimensions.map(name => ({ name })),
        metrics: [
          { name: 'eventCount' },
          { name: 'eventCountPerUser' },
        ],
        orderBys: [
          {
            metric: { metricName: 'eventCount' },
            desc: true,
          },
        ],
        limit: args.limit,
      };

      // Add event name filter if specified
      if (args.eventName) {
        (request as any).dimensionFilter = {
          filter: {
            fieldName: 'eventName',
            stringFilter: {
              matchType: 'EXACT',
              value: args.eventName,
            },
          },
        };
      }

      const [response] = await this.analyticsClient.runReport(request);
      const formattedResponse = formatGAResponse(response);
      
      return createSuccessResponse(formattedResponse, {
        dateRange: {
          startDate: args.startDate,
          endDate: args.endDate,
        },
        dimensions: args.dimensions,
        eventFilter: args.eventName,
        totalRows: formattedResponse.metadata?.rowCount || 0,
      });
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error occurred';
      logger.error('Events tool error', { error: errorMessage, args });
      throw new McpError(
        ErrorCode.InternalError,
        `Google Analytics API request failed: ${errorMessage}`
      );
    }
  }

  /**
   * Handle user behavior data retrieval
   */
  private async handleUserBehavior(args: GetUserBehaviorInput): Promise<any> {
    try {
      const request = {
        property: `properties/${this.propertyId}`,
        dateRanges: [
          {
            startDate: args.startDate,
            endDate: args.endDate,
          },
        ],
        dimensions: args.dimensions.map(name => ({ name })),
        metrics: [
          { name: 'screenPageViews' },
          { name: 'userEngagementDuration' },
          { name: 'bounceRate' },
          { name: 'engagementRate' },
          { name: 'averageSessionDuration' },
        ],
        orderBys: [
          {
            metric: { metricName: 'userEngagementDuration' },
            desc: true,
          },
        ],
        limit: args.limit,
      };

      const [response] = await this.analyticsClient.runReport(request);
      const formattedResponse = formatGAResponse(response);
      
      return createSuccessResponse(formattedResponse, {
        dateRange: {
          startDate: args.startDate,
          endDate: args.endDate,
        },
        dimensions: args.dimensions,
        totalRows: formattedResponse.metadata?.rowCount || 0,
      });
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error occurred';
      logger.error('User Behavior tool error', { error: errorMessage, args });
      throw new McpError(
        ErrorCode.InternalError,
        `Google Analytics API request failed: ${errorMessage}`
      );
    }
  }

  /**
   * Setup Express server with middleware and CORS
   */
  private setupExpress(): void {
    // Setup CORS
    this.app.use(cors({
      origin: config.http.cors.origins,
      allowedHeaders: config.http.cors.allowedHeaders,
      exposedHeaders: config.http.cors.exposedHeaders,
      credentials: true,
    }));

    // Setup JSON parsing
    this.app.use(express.json());

    // Setup request logging
    this.app.use((req: Request, res: Response, next) => {
      logger.debug('HTTP Request', {
        method: req.method,
        url: req.url,
        headers: req.headers,
      });
      next();
    });

    // Health check endpoint
    this.app.get('/health', (req: Request, res: Response) => {
      res.json({ status: 'healthy', timestamp: new Date().toISOString() });
    });

    // OAuth Protected Resource Metadata endpoint (RFC9728)
    this.app.get('/.well-known/oauth-protected-resource', (req: Request, res: Response) => {
      if (config.auth.mode === 'oauth') {
        res.json({
          resource: config.auth.resourceUri,
          authorization_servers: [config.auth.domain],
          scopes_supported: ['read:analytics'],
          bearer_methods_supported: ['header'],
          resource_documentation: 'https://github.com/nalyk/mcp-server-google-analytics'
        });
      } else {
        res.status(404).json({ error: 'OAuth mode not enabled' });
      }
    });

    logger.info('Express server configured with CORS and middleware');
  }

  /**
   * Start the server
   */
  async start(): Promise<void> {
    logger.info('Starting Google Analytics MCP server');

    if (config.transport === 'stdio') {
      // STDIO transport mode for typical MCP clients (default)
      logger.info('Using STDIO transport (default)');
      const stdio = new StdioServerTransport();
      await this.server.connect(stdio);
      // In stdio mode we do not start the HTTP server
      return;
    }

    // HTTP transport mode
    logger.info('Using HTTP transport');
    const isStateless = config.http.sessionMode === 'stateless';
    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: isStateless ? undefined : () => Math.random().toString(36).substring(2, 15),
    });
    await this.server.connect(transport);

    // Setup authentication middleware for MCP endpoints
    const authMiddleware = this.setupAuthenticationMiddleware();

    // Setup MCP HTTP endpoints with optional authentication
    this.app.post('/mcp', authMiddleware as any, async (req: Request, res: Response) => {
      try {
        await transport.handleRequest(req as any, res as any, req.body);
      } catch (error) {
        logger.error('MCP request handling error', { error });
        if (!res.headersSent) {
          res.status(500).json({
            jsonrpc: '2.0',
            error: { code: -32603, message: 'Internal server error' },
            id: null,
          });
        }
      }
    });

    // Setup SSE endpoint for server-to-client notifications
    this.app.get('/mcp', authMiddleware as any, async (req: Request, res: Response) => {
      try {
        await transport.handleRequest(req as any, res as any);
      } catch (error) {
        logger.error('MCP SSE handling error', { error });
        if (!res.headersSent) {
          res.status(500).send('Internal server error');
        }
      }
    });

    // Start HTTP server
    const server = this.app.listen(config.http.port, config.http.host, () => {
      logger.info(`Google Analytics MCP server running on http://${config.http.host}:${config.http.port}`);
      logger.info(`Health check available at http://${config.http.host}:${config.http.port}/health`);
      logger.info(`MCP endpoint available at http://${config.http.host}:${config.http.port}/mcp`);
    });

    // Graceful shutdown
    process.on('SIGTERM', () => {
      logger.info('SIGTERM received, shutting down gracefully');
      server.close(() => {
        logger.info('HTTP server closed');
        process.exit(0);
      });
    });

    process.on('SIGINT', () => {
      logger.info('SIGINT received, shutting down gracefully');
      server.close(() => {
        logger.info('HTTP server closed');
        process.exit(0);
      });
    });
  }

  /**
   * Setup authentication middleware based on configuration
   */
  private setupAuthenticationMiddleware() {
    if (this.authConfig.enabled) {
      if (config.auth.mode === 'jwt' || config.auth.mode === 'oauth') {
        try {
          return createAuthMiddlewareFromEnv();
        } catch (error) {
          logger.error('Failed to create authentication middleware', { error });
          throw error;
        }
      }
    }
    
    // Return no-op middleware for 'none' mode
    return (req: any, res: any, next: any) => next();
  }
}

// Create and export the server instance
export const googleAnalyticsServer = new GoogleAnalyticsServer();
