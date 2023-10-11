/*
api/index.js mounts all routes inside the api folder
these routes are mounted in ../server.js on the route '/api'
*/
import { Router } from 'express';
import models from './models/index.js';
import auth from './auth/index.js';
import docs from './docs/index.js';

const router = Router();

router.get('/', (req, res) => {
  res.json({
    message: 'API is working'
  });
});

router.use('/models', models);
router.use('/auth', auth);
router.use('/docs', docs);


export default router;