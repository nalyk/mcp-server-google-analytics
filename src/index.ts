#!/usr/bin/env node

/**
 * MCP Google Analytics Server - Refactored Entry Point
 * Modern, modular implementation using the latest MCP SDK
 */

import { googleAnalyticsServer } from './lib/server';
import logger from './utils/logger';

/**
 * Main function to start the MCP Google Analytics server
 */
async function main(): Promise<void> {
  try {
    logger.info('Starting Google Analytics MCP Server...');
    
    // Start the server
    await googleAnalyticsServer.start();
    
    // Server is now running and ready to accept requests
    logger.info('Server is running and ready to accept requests');
    
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    logger.error('Failed to start server', { error: errorMessage });
  }
}

// Handle unhandled promise rejections
process.on('unhandledRejection', (reason, promise) => {
  logger.error('Unhandled Rejection', { reason, promise: String(promise) });
  process.exit(1);
});

// Handle uncaught exceptions
process.on('uncaughtException', (error) => {
  logger.error('Uncaught Exception', { error: error.message, stack: error.stack });
  process.exit(1);
});

// Start the server
main().catch((error) => {
  logger.error('Fatal error during startup', {
    error: error instanceof Error ? error.message : String(error),
    stack: error instanceof Error ? error.stack : undefined
  });
  process.exit(1);
});