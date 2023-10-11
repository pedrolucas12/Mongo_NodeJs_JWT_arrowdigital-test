/*
api/models/index.js mounts all routes inside the models folder
these routes are mounted in ../../server.js on the route '/api/models'
*/
import { Router } from 'express';
import lab from './lab.js';
import clinic from './clinic.js';
import collaborator from './collaborator.js';
import inventory from './inventory.js';
import order from './order.js';
import service from './service.js';
import user from './user.js';
import pandaScan from './pandaScan.js';

const router = Router();
router.use('/lab', lab);
router.use('/clinic', clinic);
router.use('/collaborator', collaborator);
router.use('/inventory', inventory);
router.use('/order', order);
router.use('/service', service);
router.use('/user', user);
router.use('/pandaScan', pandaScan);

export default router;