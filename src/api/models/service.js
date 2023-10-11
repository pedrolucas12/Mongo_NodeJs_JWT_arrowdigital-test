import { Router } from 'express';
import { Service } from '../../data/mongooseModels.js';

const router = Router();

/**
 * @description return all services
 * @param {Express<Request>} req the request object
 * @param {Express<Response>} res the response object
 */
router.get('/', (req, res, next) => {
  Service.find()
    .then((services) => {
      if (!services) {
        res.status(400).json({ message: 'No services found' });
      } else res.json(services);
    })
    .catch((err) => {
      res.status(500).json({ message: err });
    });
});

/**
 * @description return one service
 * @param {Express<Request>} req the request object
 * @param {Express<Response>} res the response object
 */
router.get('/:id', (req, res, next) => {
  Service.findById(req.params.id)
    .then((service) => {
      if (!service) {
        res.status(400).json({ message: 'No service found' });
      } else {
        res.json(service);
      }
    })
    .catch((err) => {
      res.status(500).json({ message: err });
    });
});

/**
 * @description create one service
 * @param {Express<Request>} req the request object
 * @param {Express<Response>} res the response object
 */
router.post('/', (req, res, next) => {
  const service = new Service(req.body);
  service.save()
    .then(() => {
      res.json(service);
    })
    .catch((err) => {
      res.status(500).json({ message: err });
    });
});

/**
 * @description update one service
 * @param {Express<Request>} req the request object
 * @param {Express<Response>} res the response object
 */
router.put('/:id', (req, res, next) => {
  Service.findOneAndUpdate({ _id: req.params.id }, { $set: req.body })
    .then(() => {
      res.json(true);
    })
    .catch((err) => {
      res.status(500).json({ code: 500, message: err });
    });
});

/**
 * @description delete one service
 * @param {Express<Request>} req the request object
 * @param {Express<Response>} res the response object
 */
router.put('/:id', (req, res, next) => {
  Service.deleteOne({ _id: req.params.id })
    .then(() => {
      res.json(true);
    })
    .catch((err) => {
      res.status(500).json({ code: 500, message: err });
    });
});

export default router;
