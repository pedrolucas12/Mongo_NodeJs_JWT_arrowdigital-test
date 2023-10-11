/*
api/auth/index.js mounts all routes inside the models folder
these routes are mounted in ../../server.js on the route '/api/auth'
*/
import { Router } from 'express';
import authController from './authController.js';

const router = Router();

router.get('/', (req, res, next) => {
  res.json({
    message: 'auth API'
  });
});

router.use('/auth', authController);

export default router;
