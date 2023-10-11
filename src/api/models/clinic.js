import { Router } from 'express';
import { Clinic } from '../../data/mongooseModels.js';

const router = Router();

/**
 * @description return all clinics
 * @param {Express<Request>} req the request object
 * @param {Express<Response>} res the response object
 */
router.get('/', (req, res) => {
  Clinic.find()
    .then((clinics) => {
      if (!clinics) {
        res.status(400).json({ message: 'No clinics found' });
      } else res.json(clinics);
    })
    .catch((err) => {
      res.status(500).json({ message: err });
    });
});

/**
 * @description return one clinic
 * @param {Express<Request>} req the request object
 * @param {Express<Response>} res the response object
 */
router.get('/:id', (req, res) => {
  Clinic.findById(req.params.id)
    .then((clinic) => {
      if (!clinic) {
        res.status(400).json({ message: 'No clinic found' });
      } else {
        res.json(clinic);
      }
    })
    .catch((err) => {
      res.status(500).json({ message: err });
    });
});

/**
 * @description create one clinic
 * @param {Express<Request>} req the request object
 * @param {Express<Response>} res the response object
 */
router.post('/', (req, res) => {
  const clinic = new Clinic(req.body);
  clinic.save()
    .then(() => {
      res.json(clinic);
    })
    .catch((err) => {
      res.status(500).json({ message: err });
    });
});

/**
 * @description update one clinic
 * @param {Express<Request>} req the request object
 * @param {Express<Response>} res the response object
 */
router.put('/:id', (req, res) => {
  Clinic.findOneAndUpdate({ _id: req.params.id }, { $set: req.body })
    .then(() => {
      res.json(true);
    })
    .catch((err) => {
      res.status(500).json({ code: 500, message: err });
    });
});

/**
 * @description delete one clinic
 * @param {Express<Request>} req the request object
 * @param {Express<Response>} res the response object
 */
router.put('/:id', (req, res) => {
  Clinic.deleteOne({ _id: req.params.id })
    .then(() => {
      res.json(true);
    })
    .catch((err) => {
      res.status(500).json({ code: 500, message: err });
    });
});

export default router;
