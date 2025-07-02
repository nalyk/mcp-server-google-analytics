/**
 * Utility functions for the MCP Google Analytics server
 */

import { z } from 'zod';

/**
 * Validates input data against a Zod schema
 * @param schema - The Zod schema to validate against
 * @param data - The data to validate
 * @returns Validated data or throws an error
 */
export function validateInput<T>(schema: z.ZodSchema<T>, data: unknown): T {
  try {
    return schema.parse(data);
  } catch (error) {
    if (error instanceof z.ZodError) {
      const errorMessages = error.errors.map(err => 
        `${err.path.join('.')}: ${err.message}`
      ).join(', ');
      throw new Error(`Validation failed: ${errorMessages}`);
    }
    throw error;
  }
}

/**
 * Formats a date string to YYYY-MM-DD format
 * @param date - Date object or string
 * @returns Formatted date string
 */
export function formatDate(date: Date | string): string {
  const d = typeof date === 'string' ? new Date(date) : date;
  return d.toISOString().split('T')[0];
}

/**
 * Creates a standardized error response
 * @param message - Error message
 * @param code - Error code (optional)
 * @returns Formatted error object
 */
export function createError(message: string, code?: string) {
  return {
    error: {
      message,
      code: code || 'UNKNOWN_ERROR',
      timestamp: new Date().toISOString(),
    },
  };
}

/**
 * Creates a standardized success response
 * @param data - Response data
 * @param metadata - Optional metadata
 * @returns Formatted success response
 */
export function createSuccessResponse<T>(data: T, metadata?: Record<string, any>) {
  return {
    data,
    metadata: {
      timestamp: new Date().toISOString(),
      ...metadata,
    },
  };
}

/**
 * Safely parses JSON with error handling
 * @param jsonString - JSON string to parse
 * @returns Parsed object or null if parsing fails
 */
export function safeJsonParse(jsonString: string): any | null {
  try {
    return JSON.parse(jsonString);
  } catch {
    return null;
  }
}

/**
 * Checks if a date range is valid (start <= end)
 * @param startDate - Start date string
 * @param endDate - End date string
 * @returns True if valid, false otherwise
 */
export function isValidDateRange(startDate: string, endDate: string): boolean {
  return new Date(startDate) <= new Date(endDate);
}

/**
 * Converts Google Analytics API response to a more readable format
 * @param response - Raw GA4 API response
 * @returns Formatted response
 */
export function formatGAResponse(response: any) {
  if (!response || !response.rows) {
    return { rows: [], totals: {} };
  }

  return {
    rows: response.rows.map((row: any) => ({
      dimensions: row.dimensionValues?.map((d: any) => d.value) || [],
      metrics: row.metricValues?.map((m: any) => ({
        value: m.value,
        oneTimeValue: m.oneTimeValue,
      })) || [],
    })),
    totals: response.totals || {},
    metadata: {
      dimensionHeaders: response.dimensionHeaders || [],
      metricHeaders: response.metricHeaders || [],
      rowCount: response.rowCount || 0,
    },
  };
}