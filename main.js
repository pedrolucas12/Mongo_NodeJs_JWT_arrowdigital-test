
import app from './src/index.js';
import logger from './src/util/logger.js';
import { connectToMongoDB } from './src/data/mongooseController.js';

const port = process.env.PORT || 8888;

const main = async () => {
  await connectToMongoDB();
  /*
  before uncommenting, add your database and collections to the mongo class in ./server/data/db
  app.locals.collection = collection;
  */
  app.listen(port, () => {
    logger.ready(`Listening: http://localhost:${port}`);
  });
};

main();
