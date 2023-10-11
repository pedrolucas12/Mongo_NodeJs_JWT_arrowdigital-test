import { Router } from 'express';
import { Inventory } from '../../data/mongooseModels.js';

const router = Router();

/**
 * @description return all inventories
 * @param {Express<Request>} req the request object
 * @param {Express<Response>} res the response object
 */
router.get('/', (req, res) => {
  Inventory.find()
    .then((inventories) => {
      if (!inventories) {
        res.status(400).json({ message: 'No inventories found' });
      } else res.json(inventories);
    })
    .catch((err) => {
      res.status(500).json({ message: err });
    });
});

/**
 * @description return one inventory
 * @param {Express<Request>} req the request object
 * @param {Express<Response>} res the response object
 */
router.get('/:id', (req, res) => {
  Inventory.findById(req.params.id)
    .then((inventory) => {
      if (!inventory) {
        res.status(400).json({ message: 'No inventory found' });
      } else {
        res.json(inventory);
      }
    })
    .catch((err) => {
      res.status(500).json({ message: err });
    });
});

/**
 * @description create one inventory
 * @param {Express<Request>} req the request object
 * @param {Express<Response>} res the response object
 */
router.post('/', (req, res) => {
  const inventory = new Inventory(req.body);
  inventory.save()
    .then(() => {
      res.json(inventory);
    })
    .catch((err) => {
      res.status(500).json({ message: err });
    });
});

/**
 * @description update one inventory
 * @param {Express<Request>} req the request object
 * @param {Express<Response>} res the response object
 */
router.put('/:id', (req, res) => {
  Inventory.findOneAndUpdate({ _id: req.params.id }, { $set: req.body })
    .then(() => {
      res.json(true);
    })
    .catch((err) => {
      res.status(500).json({ code: 500, message: err });
    });
});

/**
 * @description delete one inventory
 * @param {Express<Request>} req the request object
 * @param {Express<Response>} res the response object
 */
router.put('/:id', (req, res) => {
  Inventory.deleteOne({ _id: req.params.id })
    .then(() => {
      res.json(true);
    })
    .catch((err) => {
      res.status(500).json({ code: 500, message: err });
    });
});

export default router;
