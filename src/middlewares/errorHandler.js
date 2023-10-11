import logger from '../util/logger.js';

export const notFound = (req, res, next) => {
  res.status(404);
  const error = new Error(`404 - Not Found - ${req.originalUrl}`);
  next(error);
}

/**
 * @description Express middleware function that handles errors and sends a JSON response with an error message and stack trace.
 * @todo This function should handle errors differently depending on the type of error.
 * @param {Error} err - The error object to handle.
 * @param {Express<Request>} req - The Express request object.
 * @param {Express<Response>} res - The Express response object.
 * @param {Function} next - The next middleware function in the chain.
 * @returns {void}
 */
export const errorHandler = (err, req, res, next) => {
  const statusCode = res.statusCode !== 200 ? res.statusCode : 500;
  res.status(statusCode);
  res.json({
    message: err.message,
    stack: process.env.NODE_ENV === 'PRODUCTION' ? 'do not panic' : err.stack
  });
  logger.error(err);
  next();
}
