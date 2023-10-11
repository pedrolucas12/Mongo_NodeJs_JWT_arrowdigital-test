import { ObjectId } from 'mongodb';
import mongoose from 'mongoose';

// Define mongoose schema for each collection
export const clinicSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    description: 'must be a string and is required'
  },
  address: {
    type: String,
    required: true,
    description: 'must be a string and is required'
  },
  patients: {
    type: [Object],
    required: true,
    description: 'must be an array of objects and is required'
  },
  dentists: {
    type: [Object],
    required: true,
    description: 'must be an array of objects and is required'
  },
  orders: {
    type: [mongoose.Schema.Types.ObjectId],
    required: true,
    description: 'must be an array of objectIds and is required'
  },
  balance: {
    type: [{
      _id: {
        type: mongoose.Schema.Types.ObjectId,
        description: 'must be an objectId and is optional'
      },
      value: {
        type: Number,
        required: true,
        description: 'must be a number and is required'
      },
      createdAt: {
        type: Date,
        required: true,
        description: 'must be a date and is required'
      },
      expiresAt: {
        type: Date,
        required: true,
        description: 'must be a date and is required'
      },
      order: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Order',
        description: 'must be an objectId and is optional'
      },
      service: {
        type: mongoose.Schema.Types.ObjectId,
        description: 'must be an objectId and is optional, references the service in the order'
      }
    }],
  },
  outstandingBalance: {
    type: Number,
    required: true,
    description: 'must be a number and is required'
  },
  email: {
    type: String,
    description: 'must be a string and is optional'
  },
  phone: {
    type: String,
    description: 'must be a string and is optional'
  },
  taxid: {
    type: String,
    description: 'must be a string and is optional'
  }
});

const collaboratorSchema = new mongoose.Schema({
  lab: {
    type: mongoose.Schema.Types.ObjectId,
    description: 'must be an objectId and is optional'
  },
  name: {
    type: String,
    required: true,
    description: 'must be a string and is required'
  },
  email: {
    type: String,
    description: 'must be a string and is optional'
  },
  phone: {
    type: String,
    description: 'must be a string and is optional'
  },
  taxid: {
    type: String,
    description: 'must be a string and is optional'
  },
  role: {
    type: String,
    description: 'must be a string and is optional'
  },
  type: {
    type: String,
    description: 'must be a string and is optional'
  },
  comission: {
    type: Number,
    description: 'must be a number and is optional'
  },
  bankInfo: {
    type: Object,
    description: 'must be an object and is optional'
  },
  salary: {
    type: Number,
    description: 'must be a number and is optional'
  },
  address: {
    type: String,
    description: 'must be a string and is optional'
  }
});

const labSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    description: 'must be a string and is required'
  },
  address: {
    type: String,
    description: 'must be a string and is optional'
  },
  clinics: {
    type: [{
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Clinic'
    }],
    description: 'must be an array of objectIds from the clinics collection and is optional'
  },
  users: {
    type: [{
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    }],
    description: 'must be an array of objectIds from the users collection and is optional'
  },
  collaborators: {
    type: [{
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Collaborator'
    }],
    description: 'must be an array of objectIds from the users collection and is optional'
  },
  orders: {
    type: [{
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Order'
    }],
    description: 'must be an array of objectIds from the orders collection and is optional'
  },
  services: {
    type: [{
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Service'
    }],
    description: 'must be an array of objectIds from the services collection and is optional'
  },
  inventory: {
    type: [{
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Inventory'
    }],
    description: 'must be an array of objectIds from the inventory collection and is optional'
  },
  revenue: {
    type: [{
      _id: {
        type: mongoose.Schema.Types.ObjectId,
        required: true,
        description: 'must be an objectId and is required'
      },
      type: {
        type: String,
        required: true,
        description: 'must be a string and is required'
      },
      value: {
        type: Number,
        required: true,
        description: 'must be a number and is required'
      },
      createdAt: {
        type: Date,
        required: true,
        description: 'must be a date and is required'
      },
      expiresAt: {
        type: Date,
        required: true,
        description: 'must be a date and is required'
      },
      collaborator: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Collaborator',
        description: 'must be an objectId and is optional'
      },
      clinic: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Clinic',
        description: 'must be an objectId and is optional'
      },
      state: {
        type: String,
        required: true,
        description: 'must be a string and is required'
      },
      bankAccount: {
        type: Object,
        description: 'must be an object, contains the Lab`s Bank Data, and is optional'
      },
      paymentInfo: {
        type: Object,
        description: 'must be an object, contains InterestRate modifier, is optional'
      }
    }],
    required: true,
    description: 'must be an array of objects and is required'
  },
  email: {
    type: String,
    description: 'must be a string and is optional'
  },
  taxid: {
    type: String,
    description: 'must be a string and is optional'
  },
  phone: {
    type: String,
    description: 'must be a string and is optional'
  }
});

const orderSchema = new mongoose.Schema({
  status: {
    type: String,
    required: true,
    description: 'must be a string and is required'
  },
  clinic: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Clinic',
    description: 'must be an objectId from the clinic collection and is optional'
  },
  dentist: {
    type: mongoose.Schema.Types.ObjectId,
    description: 'must be an objectId from the dentists array in the clinic collection and is optional'
  },
  lab: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Lab',
    description: 'must be an objectId from the lab collection and is optional'
  },
  patient: {
    type: mongoose.Schema.Types.ObjectId,
    description: 'must be an objectId from the patients array in the clinic collection and is optional'
  },
  services: {
    type: [{
      _id: {
        type: mongoose.Schema.Types.ObjectId,
        description: 'must be an objectId and is optional'
      },
      createdAt: {
        type: Date,
        required: true,
        description: 'must be a date and is required'
      },
      createdBy: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        description: 'must be an objectId from the user collection and is optional'
      },
      expiresAt: {
        type: Date,
        required: true,
        description: 'must be a date and is required'
      },
      service: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Service',
        description: 'must be an objectId from the service collection and is optional'
      },
      collaborator: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Collaborator',
        description: 'must be an objectId from the collaborator collection and is optional'
      },
      finalvalue: {
        type: Number,
        required: true,
        description: 'must be a number and is required'
      },
      state: {
        type: String,
        required: true,
        description: 'must be a string and is required'
      },
      teeth: {
        type: [Number],
        description: 'must be an array of numbers and is optional'
      },
      jaw: {
        type: [Number],
        description: 'must be an array of numbers and is optional'
      },
      discount: {
        type: Number,
        required: true,
        description: 'must be a number and is required'
      }
    }],
    required: true,
    description: 'must be an array of objects and is required'
  },
  description: {
    type: String,
    required: true,
    description: 'must be a string and is required'
  },
  state: {
    type: String,
    required: true,
    description: 'must be a string and is required'
  },
  createdAt: {
    type: Date,
    required: true,
    description: 'must be a date and is required'
  },
  expiresAt: {
    type: Date,
    required: true,
    description: 'must be a date and is required'
  },
  comments: {
    type: [{
      createdAt: {
        type: Date,
        required: true,
        description: 'must be a date and is required'
      },
      createdBy: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        description: 'must be an objectId from the user collection and is optional'
      },
      content: {
        type: String,
        required: true,
        description: 'must be a string and is required'
      },
      type: {
        type: String,
        required: true,
        description: 'must be a string and is required'
      }
    }],
    required: true,
    description: 'must be an array of objects and is required'
  },
  tag: {
    type: [String],
    required: true,
    description: 'must be an array of strings and is required'
  }
});

const userSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    description: 'must be a string and is required'
  },
  password: {
    type: String,
    required: true,
    description: 'must be a string and is required'
  },
  lab: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Lab',
    description: 'must be an objectId from the lab collection and is optional'
  },
  clinic: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Clinic',
    description: 'must be an objectId from the clinic collection and is optional'
  },
  email: {
    type: String,
    description: 'must be a string and is optional'
  },
  permissions: {
    type: [String],
    description: 'must be an array of strings and is optional'
  }
});

const pandaScanSchema = new mongoose.Schema({
  id: {
    type: String,
    required: true,
    description: 'must be a string and is required'
  },
  sourceName: {
    type: String,
    required: true,
    description: 'must be a string and is required'
  },
  targetName: {
    type: String,
    required: true,
    description: 'must be a string and is required'
  },
  targetCreditCode: {
    type: String,
    required: true,
    description: 'must be a string and is required'
  },
  name: {
    type: String,
    required: true,
    description: 'must be a string and is required'
  },
  type: {
    type: String,
    required: true,
    description: 'must be a string and is required'
  },
  patientName: {
    type: String,
    required: true,
    description: 'must be a string and is required'
  },
  doctorName: {
    type: String,
    required: true,
    description: 'must be a string and is required'
  },
  notes: {
    type: String,
    required: true,
    description: 'must be a string and is required'
  },
  time: {
    type: Date,
    required: true,
    description: 'must be a date and is required'
  },
  expires: {
    type: Date,
    required: true,
    description: 'must be a date and is required'
  },
  size: {
    type: Number,
    required: true,
    description: 'must be a number and is required'
  },
  url: {
    type: String,
    required: true,
    description: 'must be a string and is required'
  },
  code: {
    type: Number,
    required: true,
    description: 'must be a number and is required'
  },
  material: {
    type: String,
    required: true,
    description: 'must be a string and is required'
  },
  color: {
    type: String,
    required: true,
    description: 'must be a string and is required'
  },
  number: {
    type: String,
    required: true,
    description: 'must be a string and is required'
  },
  referenceOrder: {
    type: ObjectId,
    describe: 'must be an objectId and is optional, references an order id'
  },
  referenceService: {
    type: ObjectId,
    describe: 'must be an objectId and is optional, reference to a service in the order'
  }
});

const serviceSchema = new mongoose.Schema({
  lab: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Lab',
    description: 'must be an objectId from the lab collection and is optional'
  },
  clinic: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Clinic',
    description: 'must be an objectId from the clinic collection and is optional'
  },
  name: {
    type: String,
    description: 'must be a string and is optional'
  },
  description: {
    type: String,
    description: 'must be a string and is optional'
  },
  value: {
    type: Number,
    description: 'must be a number and is optional'
  },
  valueType: {
    type: String,
    required: true,
    description: 'must be a string and is required'
  },
  type: {
    type: String,
    required: true,
    description: 'must be a string and is required'
  },
});

const inventorySchema = new mongoose.Schema({
  lab: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Lab',
    description: 'must be an objectId from the lab collection and is optional'
  },
  clinic: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Clinic',
    description: 'must be an objectId from the clinic collection and is optional'
  },
  amount: {
    type: Number,
    description: 'must be a number and is optional'
  },
  description: {
    type: String,
    description: 'must be a string and is optional'
  },
  name: {
    type: String,
    description: 'must be a string and is optional'
  },
  value: {
    type: Number,
    description: 'must be a number and is optional'
  },
  type: {
    type: String,
    description: 'must be a string and is optional'
  }
});

export const Clinic = mongoose.model('Clinic', clinicSchema);
export const Collaborator = mongoose.model('Collaborator', collaboratorSchema);
export const Lab = mongoose.model('Lab', labSchema);
export const Order = mongoose.model('Order', orderSchema);
export const User = mongoose.model('User', userSchema);
export const PandaScan = mongoose.model('PandaScan', pandaScanSchema);
export const Service = mongoose.model('Service', serviceSchema);
export const Inventory = mongoose.model('Inventory', inventorySchema);

// todo: add user as separate entity