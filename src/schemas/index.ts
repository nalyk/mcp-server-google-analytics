/**
 * Input validation schemas using Zod
 * These schemas validate all incoming tool parameters
 */

import { z } from 'zod';

// Date validation helper
const dateString = z.string().regex(/^\d{4}-\d{2}-\d{2}$/, 'Date must be in YYYY-MM-DD format');

// Base date range object schema
const baseDateRangeSchema = z.object({
  startDate: dateString,
  endDate: dateString,
});

// Date range validation function
const validateDateRange = (data: { startDate: string; endDate: string }) => {
  return new Date(data.startDate) <= new Date(data.endDate);
};

// Tool-specific schemas
export const GetPageViewsSchema = z.object({
  startDate: dateString,
  endDate: dateString,
  dimensions: z.array(z.string()).default(['pagePath']),
  limit: z.number().default(10),
}).refine(
  validateDateRange,
  {
    message: "Start date must be before or equal to end date",
    path: ["startDate"],
  }
);

export const GetActiveUsersSchema = z.object({
  startDate: dateString,
  endDate: dateString,
  dimensions: z.array(z.string()).default(['country']),
  limit: z.number().default(10),
}).refine(
  validateDateRange,
  {
    message: "Start date must be before or equal to end date",
    path: ["startDate"],
  }
);

export const GetEventsSchema = z.object({
  startDate: dateString,
  endDate: dateString,
  eventName: z.string().optional(),
  dimensions: z.array(z.string()).default(['eventName']),
  limit: z.number().default(10),
}).refine(
  validateDateRange,
  {
    message: "Start date must be before or equal to end date",
    path: ["startDate"],
  }
);

export const GetUserBehaviorSchema = z.object({
  startDate: dateString,
  endDate: dateString,
  dimensions: z.array(z.string()).default(['pagePath']),
  limit: z.number().default(10),
}).refine(
  validateDateRange,
  {
    message: "Start date must be before or equal to end date",
    path: ["startDate"],
  }
);

// Export all schemas as a collection
export const schemas = {
  getPageViews: GetPageViewsSchema,
  getActiveUsers: GetActiveUsersSchema,
  getEvents: GetEventsSchema,
  getUserBehavior: GetUserBehaviorSchema,
} as const;

// Type exports for use in other modules - explicitly define the output types
export type GetPageViewsInput = {
  startDate: string;
  endDate: string;
  dimensions: string[];
  limit: number;
};

export type GetActiveUsersInput = {
  startDate: string;
  endDate: string;
  dimensions: string[];
  limit: number;
};

export type GetEventsInput = {
  startDate: string;
  endDate: string;
  eventName?: string;
  dimensions: string[];
  limit: number;
};

export type GetUserBehaviorInput = {
  startDate: string;
  endDate: string;
  dimensions: string[];
  limit: number;
};