import { Router } from 'express';
import { PandaScan } from '../../data/mongooseModels.js';

const router = Router();

/**
 * @description return all pandaScans
 * @param {Express<Request>} req the request object
 * @param {Express<Response>} res the response object
 */
router.get('/', (req, res, next) => {
  PandaScan.find()
    .then((pandaScans) => {
      if (!pandaScans) {
        res.status(400).json({ message: 'No pandaScans found' });
      } else res.json(pandaScans);
    })
    .catch((err) => {
      res.status(500).json({ message: err });
    });
});

/**
 * @description return one pandaScan
 * @param {Express<Request>} req the request object
 * @param {Express<Response>} res the response object
 */
router.get('/:id', (req, res, next) => {
  PandaScan.findById(req.params.id)
    .then((pandaScan) => {
      if (!pandaScan) {
        res.status(400).json({ message: 'No pandaScan found' });
      } else {
        res.json(pandaScan);
      }
    })
    .catch((err) => {
      res.status(500).json({ message: err });
    });
});

/**
 * @description create one pandaScan
 * @param {Express<Request>} req the request object
 * @param {Express<Response>} res the response object
 */
router.post('/', (req, res, next) => {
  const pandaScan = new PandaScan(req.body);
  pandaScan.save()
    .then(() => {
      res.json(pandaScan);
    })
    .catch((err) => {
      res.status(500).json({ message: err });
    });
});

/**
 * @description update one pandaScan
 * @param {Express<Request>} req the request object
 * @param {Express<Response>} res the response object
 */
router.put('/:id', (req, res, next) => {
  PandaScan.findOneAndUpdate({ _id: req.params.id }, { $set: req.body })
    .then(() => {
      res.json(true);
    })
    .catch((err) => {
      res.status(500).json({ code: 500, message: err });
    });
});

/**
 * @description delete one pandaScan
 * @param {Express<Request>} req the request object
 * @param {Express<Response>} res the response object
 */
router.put('/:id', (req, res, next) => {
  PandaScan.deleteOne({ _id: req.params.id })
    .then(() => {
      res.json(true);
    })
    .catch((err) => {
      res.status(500).json({ code: 500, message: err });
    });
});

export default router;
