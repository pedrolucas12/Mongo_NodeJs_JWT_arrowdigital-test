/*
api/docs/index.js mounts all routes inside the models folder
these routes are mounted in ../../server.js on the route '/api/docs'
*/
import { Router } from 'express';
import swaggerUi from 'swagger-ui-express';
import swaggerDocument from "../../public/swagger.json" assert { type: "json" };
const router = Router();

// Serve the Swagger UI for API documentation
router.use('/', swaggerUi.serve);
router.get('/', swaggerUi.setup(swaggerDocument));

export default router;
