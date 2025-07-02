/**
 * Authentication Middleware for MCP Google Analytics Server
 * Implements OAuth 2.0 JWT validation with resource indicator enforcement
 */

import { auth } from 'express-oauth2-jwt-bearer';
import { Request, Response, NextFunction } from 'express';
import logger from '../utils/logger';

/**
 * Interface for authenticated request with JWT payload
 */
export interface AuthenticatedRequest extends Request {
  auth?: {
    payload: any;
    header: any;
    token: string;
  };
}

/**
 * Configuration interface for OAuth middleware
 */
interface AuthConfig {
  domain: string;
  audience: string;
  requiredResource?: string;
}

/**
 * Create OAuth 2.0 JWT authentication middleware
 * @param config - Authentication configuration
 * @returns Express middleware function
 */
export function createAuthMiddleware(config: AuthConfig) {
  // Validate required configuration
  if (!config.domain) {
    throw new Error('AUTH0_DOMAIN is required for authentication');
  }
  
  if (!config.audience) {
    throw new Error('AUTH0_AUDIENCE is required for authentication');
  }

  // Create the base JWT validation middleware
  const jwtCheck = auth({
    audience: process.env.AUTH0_AUDIENCE,
    issuerBaseURL: process.env.AUTH0_ISSUER_URL,
    tokenSigningAlg: 'RS256',
    authRequired: true,
  });

  // Return combined middleware that validates JWT and resource indicator
  return async (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
    try {
      // First, validate the JWT token
      await new Promise<void>((resolve, reject) => {
        jwtCheck(req, res, (error: any) => {
          if (error) {
            reject(error);
          } else {
            resolve();
          }
        });
      });

      // If resource validation is required, check for the resource indicator
      if (config.requiredResource && req.auth?.payload) {
        const tokenResource = req.auth.payload.resource || req.auth.payload.aud;
        
        // Check if the token contains the required resource indicator
        if (Array.isArray(tokenResource)) {
          if (!tokenResource.includes(config.requiredResource)) {
            return res.status(403).json({
              error: 'insufficient_scope',
              error_description: `Token does not contain required resource: ${config.requiredResource}`,
            });
          }
        } else if (tokenResource !== config.requiredResource) {
          return res.status(403).json({
            error: 'insufficient_scope',
            error_description: `Token does not contain required resource: ${config.requiredResource}`,
          });
        }
      }

      // Authentication and authorization successful
      next();
    } catch (error) {
      logger.error('Authentication failed', {
        error: error instanceof Error ? error.message : String(error),
        stack: error instanceof Error ? error.stack : undefined
      });
      
      // Handle different types of authentication errors
      if (error instanceof Error) {
        if (error.message.includes('jwt malformed') || error.message.includes('invalid token')) {
          return res.status(401).json({
            error: 'invalid_token',
            error_description: 'The access token is malformed or invalid',
          });
        }
        
        if (error.message.includes('jwt expired')) {
          return res.status(401).json({
            error: 'token_expired',
            error_description: 'The access token has expired',
          });
        }
        
        if (error.message.includes('audience invalid')) {
          return res.status(401).json({
            error: 'invalid_audience',
            error_description: 'The access token audience is invalid',
          });
        }
      }

      // Generic authentication error with WWW-Authenticate header for OAuth mode
      const authHeader = config.requiredResource 
        ? `Bearer realm="MCP Server", resource="${config.requiredResource}"`
        : 'Bearer realm="MCP Server"';
        
      return res.status(401)
        .header('WWW-Authenticate', authHeader)
        .json({
          error: 'unauthorized',
          error_description: 'Authentication required',
        });
    }
  };
}

/**
 * Create authentication middleware from environment variables
 * @returns Express middleware function configured from environment
 */
export function createAuthMiddlewareFromEnv() {
  const domain = process.env.AUTH0_DOMAIN;
  const audience = process.env.AUTH0_AUDIENCE;
  const requiredResource = process.env.MCP_SERVER_RESOURCE;

  if (!domain || !audience) {
    throw new Error(
      'Authentication configuration missing. Please set AUTH0_DOMAIN and AUTH0_AUDIENCE environment variables.'
    );
  }

  return createAuthMiddleware({
    domain,
    audience,
    requiredResource,
  });
}

/**
 * Utility function to extract user information from authenticated request
 * @param req - Authenticated request object
 * @returns User information from JWT payload
 */
export function getUserFromRequest(req: AuthenticatedRequest) {
  if (!req.auth?.payload) {
    return null;
  }

  const payload = req.auth.payload;
  
  return {
    sub: payload.sub,
    email: payload.email,
    name: payload.name,
    picture: payload.picture,
    permissions: payload.permissions || [],
    scope: payload.scope,
    resource: payload.resource || payload.aud,
  };
}

/**
 * Middleware to check for specific permissions in the JWT token
 * @param requiredPermissions - Array of required permissions
 * @returns Express middleware function
 */
export function requirePermissions(requiredPermissions: string[]) {
  return (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
    const user = getUserFromRequest(req);
    
    if (!user) {
      return res.status(401).json({
        error: 'unauthorized',
        error_description: 'Authentication required',
      });
    }

    const userPermissions = user.permissions || [];
    const hasAllPermissions = requiredPermissions.every(permission => 
      userPermissions.includes(permission)
    );

    if (!hasAllPermissions) {
      return res.status(403).json({
        error: 'insufficient_permissions',
        error_description: `Required permissions: ${requiredPermissions.join(', ')}`,
      });
    }

    next();
  };
}