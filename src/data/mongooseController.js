import mongoose from 'mongoose';
import logger from '../util/logger.js';

/**
 * @async
 * @description connect to MongoDB with mongoose, creates a connection pool
 * @throws {Error} mongoose connection error
 */
export const connectToMongoDB = async () => {
  try {
    await mongoose.connect(process.env.DATABASE_URI).catch((err) => {
      err.message = `${err.message} [connectToMongoDB]`;
      throw err;
    });
    logger.ready('Connected to MongoDB');
  } catch (error) {
    // TODO: handle error with retry
    throw error;
  }
};

/**
 * @async
 * @description close mongoose connection
 * @throws {Error} mongoose connection error
 */
export const closeConnection = async () => {
  try {
    await mongoose.connection.close();
    logger.log('Closed MongoDB connection');
  } catch (error) {
    logger.error(`Error closing MongoDB connection: ${error.message}`);
  }
};

/**
 * @warning only for development use
 */
export const dropDatabase = async () => {
  if (process.env.NODE_ENV !== 'DEVELOPMENT') {
    logger.warn('dropDatabase should only be used in development');
    return;
  }
  try {
    await mongoose.connection.dropDatabase();
    logger.log('Dropped database');
  } catch (error) {
    logger.error(`Error dropping database: ${error.message}`);
  }
};

/**
 * @warning only for development use
 * @param {mongoose<Model>[]} modelArray - mongoose models
 */
export const createCollections = async (modelArray) => {
  if (process.env.NODE_ENV !== 'DEVELOPMENT') {
    logger.warn('createCollections should only be used in development');
    return;
  }
  try {
    await Promise.all(modelArray.map((model) => model.createCollection()));
    logger.log('Created collections');
  } catch (error) {
    logger.error(`Error creating collections: ${error.message}`);
  }
}
