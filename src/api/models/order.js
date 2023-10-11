import { Router } from 'express';
import { Order } from '../../data/mongooseModels.js';

const router = Router();

// TODO: populate order with dentist and patient from clinic table
/**
 * @description return all orders
 * @param {Express<Request>} req the request object
 * @param {Express<Response>} res the response object
 */
router.get('/', (req, res) => {
  Order.find()
    .populate('clinic')
    .then((orders) => {
      if (!orders) {
        res.status(400).json({ message: 'No orders found' });
      } else res.json(orders);
    })
    .catch((err) => {
      res.status(500).json({ message: err });
    });
});

/**
 * @description return one order
 * @param {Express<Request>} req the request object
 * @param {Express<Response>} res the response object
 */
router.get('/:id', (req, res) => {
  Order.findById(req.params.id)
    .populate('clinic')
    .then((order) => {
      if (!order) {
        res.status(400).json({ message: 'No order found' });
      } else {
        res.json(order);
      }
    })
    .catch((err) => {
      res.status(500).json({ message: err });
    });
});

/**
 * @description create one order
 * @param {Express<Request>} req the request object
 * @param {Express<Response>} res the response object
 */
router.post('/', (req, res) => {
  const order = new Order(req.body);
  order.save()
    .then(() => {
      res.json(order);
    })
    .catch((err) => {
      res.status(500).json({ message: err });
    });
});

/**
 * @description update one order
 * @param {Express<Request>} req the request object
 * @param {Express<Response>} res the response object
 */
router.put('/:id', (req, res) => {
  Order.findOneAndUpdate({ _id: req.params.id }, { $set: req.body })
    .then(() => {
      res.json(true);
    })
    .catch((err) => {
      res.status(500).json({ code: 500, message: err });
    });
});

/**
 * @description delete one order
 * @param {Express<Request>} req the request object
 * @param {Express<Response>} res the response object
 */
router.put('/:id', (req, res) => {
  Order.deleteOne({ _id: req.params.id })
    .then(() => {
      res.json(true);
    })
    .catch((err) => {
      res.status(500).json({ code: 500, message: err });
    });
});

export default router;
