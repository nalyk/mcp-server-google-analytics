import winston from 'winston';

// Get log level from environment variable, default to 'info'
const logLevel = process.env.LOG_LEVEL || 'info';

// Determine if we're in development mode
const isDevelopment = process.env.NODE_ENV === 'development';

// Create logger configuration
const logger = winston.createLogger({
  level: logLevel,
  format: isDevelopment
    ? winston.format.combine(
        winston.format.colorize(),
        winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
        winston.format.printf(({ timestamp, level, message, ...meta }) => {
          const metaString = Object.keys(meta).length ? ` ${JSON.stringify(meta)}` : '';
          return `${timestamp} [${level}]: ${message}${metaString}`;
        })
      )
    : winston.format.combine(
        winston.format.timestamp(),
        winston.format.errors({ stack: true }),
        winston.format.json()
      ),
  transports: [
    new winston.transports.Console()
  ]
});

export default logger;