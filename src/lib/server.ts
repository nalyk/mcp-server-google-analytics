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
  ListResourcesRequestSchema,
  ReadResourceRequestSchema,
  ListPromptsRequestSchema,
  GetPromptRequestSchema,
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
          tools: { listChanged: false },
          resources: { subscribe: false, listChanged: false },
          prompts: { listChanged: false },
          logging: {},
        },
        instructions:
          'MCP Google Analytics Server: exposes GA4 analytics via tools. ' +
          'Authenticate to GA via service account env vars. Tools support date ranges, optional dimensions, and limits. ' +
          'See resources for server usage and health.',
        enforceStrictCapabilities: true,
        debouncedNotificationMethods: [
          'notifications/tools/list_changed',
          'notifications/resources/list_changed',
        ],
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
    this.setupResourceHandlers();
    this.setupPromptHandlers();
  }

  /**
   * Normalize GA4 property identifier to the required resource format
   * Accepts either a numeric ID (e.g., "123456789") or a full resource ("properties/123456789").
   */
  private getPropertyResource(): string {
    const id = this.propertyId.trim();
    return id.startsWith('properties/') ? id : `properties/${id}`;
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
    this.server.setRequestHandler(CallToolRequestSchema, async (request: CallToolRequest, extra) => {
      const { name, arguments: args } = request.params;

      logger.info('Incoming tool request', { toolName: name, args });
      // Progress: if requested, send a starting progress tick
      const progressToken = (request.params as any)?._meta?.progressToken;
      const sendProgress = async (progress: number, total?: number, message?: string) => {
        if (progressToken) {
          await extra.sendNotification({
            method: 'notifications/progress',
            params: {
              progressToken,
              progress,
              ...(typeof total === 'number' ? { total } : {}),
              ...(message ? { message } : {}),
            },
          } as any);
        }
      };

      try {
        // Validate authentication before processing any tool calls
        await this.validateAuthentication(request);
        await sendProgress(0, 100, 'Validated authentication');

        switch (name) {
          case 'get_page_views': {
            const validatedArgs = validateInput(GetPageViewsSchema, args) as GetPageViewsInput;
            await sendProgress(20, 100, 'Fetching page views');
            if (extra.signal.aborted) throw new McpError(ErrorCode.InvalidRequest, 'Request was cancelled');
            const result = await this.handlePageViews(validatedArgs, extra.signal);
            await sendProgress(100, 100, 'Done');
            await this.server.sendLoggingMessage({ level: 'info', data: { tool: name, status: 'ok' } } as any, extra.sessionId);
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
            await sendProgress(20, 100, 'Fetching active users');
            if (extra.signal.aborted) throw new McpError(ErrorCode.InvalidRequest, 'Request was cancelled');
            const result = await this.handleActiveUsers(validatedArgs, extra.signal);
            await sendProgress(100, 100, 'Done');
            await this.server.sendLoggingMessage({ level: 'info', data: { tool: name, status: 'ok' } } as any, extra.sessionId);
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
            await sendProgress(20, 100, 'Fetching events');
            if (extra.signal.aborted) throw new McpError(ErrorCode.InvalidRequest, 'Request was cancelled');
            const result = await this.handleEvents(validatedArgs, extra.signal);
            await sendProgress(100, 100, 'Done');
            await this.server.sendLoggingMessage({ level: 'info', data: { tool: name, status: 'ok' } } as any, extra.sessionId);
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
            await sendProgress(20, 100, 'Fetching user behavior');
            if (extra.signal.aborted) throw new McpError(ErrorCode.InvalidRequest, 'Request was cancelled');
            const result = await this.handleUserBehavior(validatedArgs, extra.signal);
            await sendProgress(100, 100, 'Done');
            await this.server.sendLoggingMessage({ level: 'info', data: { tool: name, status: 'ok' } } as any, extra.sessionId);
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
        await this.server.sendLoggingMessage({ level: 'error', data: { tool: name, error: errorMessage } } as any, undefined);
        throw new McpError(
          ErrorCode.InternalError,
          `Tool execution failed: ${errorMessage}`
        );
      }
    });
  }

  /**
   * Setup basic resources as per MCP resources API
   */
  private setupResourceHandlers(): void {
    this.server.setRequestHandler(ListResourcesRequestSchema, async () => {
      return {
        resources: [
          {
            uri: 'mcp-ga://server/health',
            name: 'Server Health',
            mimeType: 'application/json',
          },
          {
            uri: 'mcp-ga://server/instructions',
            name: 'Usage Instructions',
            mimeType: 'text/markdown',
          },
          {
            uri: 'mcp-ga://ga/property',
            name: 'GA Property',
            mimeType: 'text/plain',
          },
        ],
      };
    });

    this.server.setRequestHandler(ReadResourceRequestSchema, async (request: any) => {
      const { uri } = request.params;
      switch (uri) {
        case 'mcp-ga://server/health':
          return {
            contents: [
              {
                uri,
                mimeType: 'application/json',
                text: JSON.stringify({ status: 'healthy', timestamp: new Date().toISOString() }),
              },
            ],
          };
        case 'mcp-ga://server/instructions':
          return {
            contents: [
              {
                uri,
                mimeType: 'text/markdown',
                text: '# MCP Google Analytics\n\nUse tools to query GA4 data. Configure GA credentials via env. Optional JWT/OAuth for HTTP transport. See README for details.',
              },
            ],
          };
        case 'mcp-ga://ga/property':
          return {
            contents: [
              {
                uri,
                mimeType: 'text/plain',
                text: this.getPropertyResource(),
              },
            ],
          };
        default:
          throw new McpError(ErrorCode.InvalidParams, `Unknown resource: ${uri}`);
      }
    });
    // Resource templates to guide clients
    const { ListResourceTemplatesRequestSchema } = require('@modelcontextprotocol/sdk/types.js');
    this.server.setRequestHandler(ListResourceTemplatesRequestSchema, async () => {
      return {
        templates: [
          {
            name: 'report',
            uriTemplate: 'mcp-ga://report?startDate={YYYY-MM-DD}&endDate={YYYY-MM-DD}&dimensions={csv}&limit={n}',
            description: 'Generic GA report template; use tools to actually fetch data',
            mimeType: 'application/json',
          },
        ],
      } as any;
    });
  }

  /**
   * Setup prompt handlers to guide clients/LLMs on common GA queries
   */
  private setupPromptHandlers(): void {
    const prompts = [
      {
        name: 'top_pages',
        description: 'Top pages by views in a date range',
        arguments: [
          { name: 'startDate', description: 'YYYY-MM-DD', required: true },
          { name: 'endDate', description: 'YYYY-MM-DD', required: true },
          { name: 'limit', description: 'Number of rows', required: false },
        ],
        template: (args: any) =>
          `Use tool get_page_views with dimensions ["pagePath"]. Parameters: ${JSON.stringify({
            startDate: args.startDate,
            endDate: args.endDate,
            dimensions: ['pagePath'],
            limit: args.limit ?? 10,
          })}`,
      },
      {
        name: 'active_users_by_country',
        description: 'Active users by country in a date range',
        arguments: [
          { name: 'startDate', description: 'YYYY-MM-DD', required: true },
          { name: 'endDate', description: 'YYYY-MM-DD', required: true },
          { name: 'limit', description: 'Number of rows', required: false },
        ],
        template: (args: any) =>
          `Use tool get_active_users with dimensions ["country"]. Parameters: ${JSON.stringify({
            startDate: args.startDate,
            endDate: args.endDate,
            dimensions: ['country'],
            limit: args.limit ?? 10,
          })}`,
      },
      {
        name: 'events_by_name',
        description: 'Event counts filtered by eventName',
        arguments: [
          { name: 'startDate', description: 'YYYY-MM-DD', required: true },
          { name: 'endDate', description: 'YYYY-MM-DD', required: true },
          { name: 'eventName', description: 'Exact event name', required: true },
          { name: 'limit', description: 'Number of rows', required: false },
        ],
        template: (args: any) =>
          `Use tool get_events with dimensions ["eventName"]. Parameters: ${JSON.stringify({
            startDate: args.startDate,
            endDate: args.endDate,
            eventName: args.eventName,
            dimensions: ['eventName'],
            limit: args.limit ?? 10,
          })}`,
      },
    ];

    this.server.setRequestHandler(ListPromptsRequestSchema, async () => {
      return {
        prompts: prompts.map(p => ({
          name: p.name,
          description: p.description,
          arguments: p.arguments,
        })),
      } as any;
    });

    this.server.setRequestHandler(GetPromptRequestSchema, async (request: any) => {
      const { name, arguments: args } = request.params;
      const prompt = prompts.find(p => p.name === name);
      if (!prompt) {
        throw new McpError(ErrorCode.InvalidParams, `Unknown prompt: ${name}`);
      }
      const text = prompt.template(args || {});
      return {
        description: prompt.description,
        messages: [
          {
            role: 'user',
            content: { type: 'text', text },
          },
        ],
      } as any;
    });
  }

  /**
   * Handle page views data retrieval
   */
  private async handlePageViews(args: GetPageViewsInput, signal?: AbortSignal): Promise<any> {
    try {
      if (signal?.aborted) throw new McpError(ErrorCode.InvalidRequest, 'Request was cancelled');
      const dimensions = args.dimensions;
      
      const request = {
        property: this.getPropertyResource(),
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

      if (signal?.aborted) throw new McpError(ErrorCode.InvalidRequest, 'Request was cancelled');
      const [response] = await this.analyticsClient.runReport(request as any);
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
  private async handleActiveUsers(args: GetActiveUsersInput, signal?: AbortSignal): Promise<any> {
    try {
      if (signal?.aborted) throw new McpError(ErrorCode.InvalidRequest, 'Request was cancelled');
      const request = {
        property: this.getPropertyResource(),
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

      if (signal?.aborted) throw new McpError(ErrorCode.InvalidRequest, 'Request was cancelled');
      const [response] = await this.analyticsClient.runReport(request as any);
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
  private async handleEvents(args: GetEventsInput, signal?: AbortSignal): Promise<any> {
    try {
      if (signal?.aborted) throw new McpError(ErrorCode.InvalidRequest, 'Request was cancelled');
      const request = {
        property: this.getPropertyResource(),
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

      if (signal?.aborted) throw new McpError(ErrorCode.InvalidRequest, 'Request was cancelled');
      const [response] = await this.analyticsClient.runReport(request as any);
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
  private async handleUserBehavior(args: GetUserBehaviorInput, signal?: AbortSignal): Promise<any> {
    try {
      if (signal?.aborted) throw new McpError(ErrorCode.InvalidRequest, 'Request was cancelled');
      const request = {
        property: this.getPropertyResource(),
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

      if (signal?.aborted) throw new McpError(ErrorCode.InvalidRequest, 'Request was cancelled');
      const [response] = await this.analyticsClient.runReport(request as any);
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
      allowedHosts: config.http.allowedHosts,
      allowedOrigins: config.http.cors.origins && config.http.cors.origins[0] !== '*' ? config.http.cors.origins : undefined,
      enableDnsRebindingProtection: config.http.dnsRebindingProtection,
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
