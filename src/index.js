import express, { json } from 'express';
import morgan from 'morgan';
import helmet from 'helmet';
import cors from 'cors';
import dotenv from 'dotenv';
import { notFound, errorHandler } from './middlewares/errorHandler.js';
import api from './api/index.js';

dotenv.config();

const app = express();

// middlewares
app.use(morgan('dev')); // logging of http calls
app.use(helmet()); // header security
app.use(cors()); // cross-origin resource sharing
app.use(json()); // json parser

// routes
app.use('/api', api); // api routes

// error handling
app.use(notFound); // 404 full path logging
app.use(errorHandler); // basic error handling

export default app;
