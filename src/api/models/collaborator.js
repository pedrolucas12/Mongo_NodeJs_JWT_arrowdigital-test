import { Router } from 'express';
import { Collaborator } from '../../data/mongooseModels.js';

const router = Router();

/**
 * @description return all collaborators
 * @param {Express<Request>} req the request object
 * @param {Express<Response>} res the response object
 */
router.get('/', (req, res) => {
  Collaborator.find()
    .then((collaborators) => {
      if (!collaborators) {
        res.status(400).json({ message: 'No collaborators found' });
      } else res.json(collaborators);
    })
    .catch((err) => {
      res.status(500).json({ message: err });
    });
});

/**
 * @description return one collaborator
 * @param {Express<Request>} req the request object
 * @param {Express<Response>} res the response object
 */
router.get('/:id', (req, res) => {
  Collaborator.findById(req.params.id)
    .then((collaborator) => {
      if (!collaborator) {
        res.status(400).json({ message: 'No collaborator found' });
      } else {
        res.json(collaborator);
      }
    })
    .catch((err) => {
      res.status(500).json({ message: err });
    });
});

/**
 * @description create one collaborator
 * @param {Express<Request>} req the request object
 * @param {Express<Response>} res the response object
 */
router.post('/', (req, res) => {
  const collaborator = new Collaborator(req.body);
  collaborator.save()
    .then(() => {
      res.json(collaborator);
    })
    .catch((err) => {
      res.status(500).json({ message: err });
    });
});

/**
 * @description update one collaborator
 * @param {Express<Request>} req the request object
 * @param {Express<Response>} res the response object
 */
router.put('/:id', (req, res) => {
  Collaborator.findOneAndUpdate({ _id: req.params.id }, { $set: req.body })
    .then(() => {
      res.json(true);
    })
    .catch((err) => {
      res.status(500).json({ code: 500, message: err });
    });
});

/**
 * @description delete one collaborator
 * @param {Express<Request>} req the request object
 * @param {Express<Response>} res the response object
 */
router.put('/:id', (req, res) => {
  Collaborator.deleteOne({ _id: req.params.id })
    .then(() => {
      res.json(true);
    })
    .catch((err) => {
      res.status(500).json({ code: 500, message: err });
    });
});

export default router;
