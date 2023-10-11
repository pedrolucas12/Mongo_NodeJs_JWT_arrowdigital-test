import { Router } from 'express';
import { User } from '../../data/mongooseModels.js';

const router = Router();

/**
 * @description return all users
 * @param {Express<Request>} req the request object
 * @param {Express<Response>} res the response object
 */
router.get('/', (req, res) => {
  User.find()
    .then((users) => {
      if (!users) {
        res.status(400).json({ message: 'No users found' });
      } else res.json(users);
    })
    .catch((err) => {
      res.status(500).json({ message: err });
    });
});

/**
 * @description return one user
 * @param {Express<Request>} req the request object
 * @param {Express<Response>} res the response object
 */
router.get('/:id', (req, res) => {
  User.findById(req.params.id)
    .then((user) => {
      if (!user) {
        res.status(400).json({ message: 'No user found' });
      } else {
        res.json(user);
      }
    })
    .catch((err) => {
      res.status(500).json({ message: err });
    });
});

/**
 * @description create one user
 * @param {Express<Request>} req the request object
 * @param {Express<Response>} res the response object
 */
router.post('/', (req, res) => {
  const user = new User(req.body);
  user.save()
    .then(() => {
      res.json(user);
    })
    .catch((err) => {
      res.status(500).json({ message: err });
    });
});

/**
 * @description update one user
 * @param {Express<Request>} req the request object
 * @param {Express<Response>} res the response object
 */
router.put('/:id', (req, res) => {
  User.findOneAndUpdate({ _id: req.params.id }, { $set: req.body })
    .then(() => {
      res.json(true);
    })
    .catch((err) => {
      res.status(500).json({ code: 500, message: err });
    });
});

/**
 * @description delete one user
 * @param {Express<Request>} req the request object
 * @param {Express<Response>} res the response object
 */
router.put('/:id', (req, res) => {
  User.deleteOne({ _id: req.params.id })
    .then(() => {
      res.json(true);
    })
    .catch((err) => {
      res.status(500).json({ code: 500, message: err });
    });
});

export default router;
