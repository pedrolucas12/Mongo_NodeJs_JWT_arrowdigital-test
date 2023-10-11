import {
  Clinic,
  Collaborator,
  Lab,
  Order,
  User,
  PandaScan,
  Service,
  Inventory
} from '../data/mongooseModels.js';
import {
  connectToMongoDB,
  dropDatabase,
  closeConnection,
  createCollections
} from '../data/mongooseController.js';
import dotenv from 'dotenv';
import logger from './logger.js';
import { faker } from '@faker-js/faker/locale/pt_BR';
import { Types } from 'mongoose';

dotenv.config();

/**
 * @async
 * @description initialize database with mock data
 */
export const initDB = async () => {
  const modelArray = [
    Lab,
    Clinic,
    Collaborator,
    Order,
    User,
    Service,
    Inventory
  ];
  try {
    await connectToMongoDB();
    await dropDatabase();
    await createCollections(modelArray);
    const modelMockData = generateMockData();
    testDocuments(modelArray, modelMockData);
    await saveDocuments(modelArray, modelMockData);
  } catch (err) {
    logger.error(err);
  } finally {
    await closeConnection();
  }
}

/**
 * @sync
 * @description generate mock lab data using faker.js
 * @returns {moongose<Document>} mocked document from lab model
 */
const generateMockLab = () => {
  const mockLab = {
    name: faker.company.name(),
    address: faker.location.streetAddress(),
    clinics: [],
    users: [],
    collaborators: [],
    orders: [],
    services: [],
    inventory: [],
    revenue: [
      {
        _id: new Types.ObjectId(),
        type: faker.helpers.arrayElement(['bill', 'invoice']),
        value: faker.finance.amount(),
        createdAt: faker.date.past(),
        expiresAt: faker.date.future(),
        collaborator: null,
        clinic: null,
        state: faker.helpers.arrayElement(['paid', 'pending', 'expired']),
        bankAccount: {
          bankName: faker.finance.accountName(),
          bankAccount: faker.finance.accountNumber(),
          bankRoutingNumber: faker.finance.routingNumber()
        },
        paymentInfo: {
          interestRate: faker.finance.amount(),
          date: faker.date.future()
        }
      },
      {
        _id: new Types.ObjectId(),
        type: faker.helpers.arrayElement(['bill', 'invoice']),
        value: faker.finance.amount(),
        createdAt: faker.date.past(),
        expiresAt: faker.date.future(),
        collaborator: null,
        clinic: null,
        state: faker.helpers.arrayElement(['paid', 'pending', 'expired']),
        bankAccount: {
          bankName: faker.finance.accountName(),
          bankAccount: faker.finance.accountNumber(),
          bankRoutingNumber: faker.finance.routingNumber()
        },
        paymentInfo: {
          interestRate: faker.finance.amount(),
          date: faker.date.future()
        }
      },
      {
        _id: new Types.ObjectId(),
        type: faker.helpers.arrayElement(['bill', 'invoice']),
        value: faker.finance.amount(),
        createdAt: faker.date.past(),
        expiresAt: faker.date.future(),
        collaborator: null,
        clinic: null,
        state: faker.helpers.arrayElement(['paid', 'pending', 'expired']),
        bankAccount: {
          bankName: faker.finance.accountName(),
          bankAccount: faker.finance.accountNumber(),
          bankRoutingNumber: faker.finance.routingNumber()
        },
        paymentInfo: {
          interestRate: faker.finance.amount(),
          date: faker.date.future()
        }
      },
    ],
    email: faker.internet.email(),
    taxid: faker.finance.accountNumber(),
    phone: faker.phone.number()
  }
  return new Lab(mockLab);
};

/**
 * @sync
 * @description generate mock clinic data using faker.js
 * @returns {moongose<Document>} mocked document from clinic model
 */
const generateMockClinic = () => {
  const mockClinic = {
    name: faker.company.name(),
    address: faker.location.streetAddress(),
    patients: [
      {
        _id: new Types.ObjectId(),
        name: faker.person.fullName(),
        email: faker.internet.email(),
        phone: faker.phone.number(),
        taxid: faker.finance.accountNumber(),
        description: faker.lorem.sentence(),
      },
      {
        _id: new Types.ObjectId(),
        name: faker.person.fullName(),
        email: faker.internet.email(),
        phone: faker.phone.number(),
        taxid: faker.finance.accountNumber(),
        description: faker.lorem.sentence(),
      },
      {
        _id: new Types.ObjectId(),
        name: faker.person.fullName(),
        email: faker.internet.email(),
        phone: faker.phone.number(),
        taxid: faker.finance.accountNumber(),
        description: faker.lorem.sentence(),
      }
    ],
    dentists: [
      {
        _id: new Types.ObjectId(),
        name: faker.person.fullName(),
        email: faker.internet.email(),
        phone: faker.phone.number(),
        taxid: faker.finance.accountNumber(),
        description: faker.lorem.sentence(),
      },
      {
        _id: new Types.ObjectId(),
        name: faker.person.fullName(),
        email: faker.internet.email(),
        phone: faker.phone.number(),
        taxid: faker.finance.accountNumber(),
        description: faker.lorem.sentence(),
      },
      {
        _id: new Types.ObjectId(),
        name: faker.person.fullName(),
        email: faker.internet.email(),
        phone: faker.phone.number(),
        taxid: faker.finance.accountNumber(),
        description: faker.lorem.sentence(),
      }
    ],
    balance: [
      {
        _id: new Types.ObjectId(),
        value: faker.finance.amount(),
        createdAt: faker.date.past(),
        expiresAt: faker.date.future(),
        order: null,
        service: null
      },
      {
        _id: new Types.ObjectId(),
        value: faker.finance.amount(),
        createdAt: faker.date.past(),
        expiresAt: faker.date.future(),
        order: null,
        service: null
      },
      {
        _id: new Types.ObjectId(),
        value: faker.finance.amount(),
        createdAt: faker.date.past(),
        expiresAt: faker.date.future(),
        order: null,
        service: null
      }
    ],
    orders: [],
    outstandingBalance: faker.finance.amount(),
    email: faker.internet.email(),
    phone: faker.phone.number(),
    taxid: faker.finance.accountNumber()
  }
  return new Clinic(mockClinic);
};

/**
 * @sync
 * @description generate mock collaborator data using faker.js
 * @returns {moongose<Document>} mocked document from collaborator model
 */
const generateMockCollaborator = () => {
  const mockCollaborator = {
    lab: null,
    name: faker.person.fullName(),
    email: faker.internet.email(),
    phone: faker.phone.number(),
    taxid: faker.finance.accountNumber(),
    role: faker.person.jobTitle(),
    type: faker.helpers.arrayElement(['employee', 'contractor']),
    comission: faker.finance.amount(),
    bankInfo: {
      bankName: faker.finance.accountName(),
      bankAccount: faker.finance.accountNumber(),
      bankRoutingNumber: faker.finance.routingNumber()
    },
    salary: faker.finance.amount(),
    address: faker.location.streetAddress()
  }
  return new Collaborator(mockCollaborator);
};

/**
 * @sync
 * @description generate mock order data using faker.js
 * @returns {moongose<Document>} mocked document from order model
 */
const generateMockOrder = () => {
  const mockOrder = {
    status: faker.helpers.arrayElement(['pending', 'in progress', 'completed']),
    clinic: null,
    dentist: null,
    lab: null,
    patient: null,
    services: [
      {
        createdAt: faker.date.past(),
        createdBy: null,
        expiresAt: faker.date.future(),
        service: null,
        collaborator: null,
        finalvalue: faker.finance.amount(),
        state: faker.helpers.arrayElement(['pending', 'in progress', 'completed']),
        teeth: [faker.number.int(), faker.number.int()],
        jaw: [faker.number.int(), faker.number.int()],
        discount: faker.finance.amount()
      },
      {
        createdAt: faker.date.past(),
        createdBy: null,
        expiresAt: faker.date.future(),
        service: null,
        collaborator: null,
        finalvalue: faker.finance.amount(),
        state: faker.helpers.arrayElement(['pending', 'in progress', 'completed']),
        teeth: [faker.number.int(), faker.number.int()],
        jaw: [faker.number.int(), faker.number.int()],
        discount: faker.finance.amount()
      },
      {
        createdAt: faker.date.past(),
        createdBy: null,
        expiresAt: faker.date.future(),
        service: null,
        collaborator: null,
        finalvalue: faker.finance.amount(),
        state: faker.helpers.arrayElement(['pending', 'in progress', 'completed']),
        teeth: [faker.number.int(), faker.number.int()],
        jaw: [faker.number.int(), faker.number.int()],
        discount: faker.finance.amount()
      }
    ],
    description: faker.lorem.sentence(),
    state: faker.helpers.arrayElement(['pending', 'in progress', 'completed']),
    createdAt: faker.date.past(),
    expiresAt: faker.date.future(),
    comments: [
      {
        createdAt: faker.date.past(),
        createdBy: null,
        content: faker.lorem.sentence(),
        type: faker.helpers.arrayElement(['note', 'warning', 'error'])
      }
    ],
    tag: [faker.word.adjective(), faker.word.adjective(), faker.word.adjective()]
  }
  return new Order(mockOrder);
};

/**
 * @sync
 * @description generate mock user data using faker.js
 * @returns {moongose<Document>} mocked document from user model
 */
const generateMockUser = () => {
  const mockUser = {
    username: faker.internet.userName(),
    password: faker.internet.password(),
    lab: null,
    clinic: null,
    email: faker.internet.email(),
    permissions: [faker.helpers.arrayElement(['admin', 'user'])]
  }
  return new User(mockUser);
};

/**
 * @sync
 * @description generate mock service data using faker.js
 * @returns {moongose<Document>} mocked document from service model
 */
const generateMockService = () => {
  const mockService = {
    lab: null,
    clinic: null,
    name: faker.commerce.productName(),
    description: faker.lorem.sentence(),
    value: faker.finance.amount(),
    valueType: faker.helpers.arrayElement(['fixed', 'teeth', 'jaw']),
    type: faker.helpers.arrayElement(['medical', 'dental', 'orthodontic'])
  }
  return new Service(mockService);
};

/**
 * @sync
 * @description generate mock inventory data using faker.js
 * @returns {moongose<Document>} mocked document from inventory model
 */
const generateMockInventory = () => {
  const mockInventory = {
    lab: null,
    clinic: null,
    name: faker.commerce.productName(),
    description: faker.lorem.sentence(),
    value: faker.finance.amount(),
    amount: faker.number.int(),
    type: faker.helpers.arrayElement(['medical', 'dental', 'orthodontic'])
  }
  return new Inventory(mockInventory);
};

/**
 * @sync
 * @description create mocked documents and link them
 * @returns {moongose<Document>[]} mocked documents
 */
const generateMockData = () => {
  const mockLab = generateMockLab();
  const mockClinic1 = generateMockClinic();
  const mockClinic2 = generateMockClinic();
  const mockClinic3 = generateMockClinic();
  const mockUser1 = generateMockUser();
  const mockUser2 = generateMockUser();
  const mockUser3 = generateMockUser();
  const mockCollaborator1 = generateMockCollaborator();
  const mockCollaborator2 = generateMockCollaborator();
  const mockCollaborator3 = generateMockCollaborator();
  const mockOrder1 = generateMockOrder();
  const mockOrder2 = generateMockOrder();
  const mockOrder3 = generateMockOrder();
  const mockOrder4 = generateMockOrder();
  const mockOrder5 = generateMockOrder();
  const mockOrder6 = generateMockOrder();
  const mockOrder7 = generateMockOrder();
  const mockOrder8 = generateMockOrder();
  const mockOrder9 = generateMockOrder();
  const mockService1 = generateMockService();
  const mockService2 = generateMockService();
  const mockService3 = generateMockService();
  const mockInventory1 = generateMockInventory();
  const mockInventory2 = generateMockInventory();
  const mockInventory3 = generateMockInventory();

  mockLab.clinics.push(mockClinic1._id, mockClinic2._id, mockClinic3._id);
  mockLab.users.push(mockUser1._id, mockUser2._id, mockUser3._id);
  mockLab.collaborators.push(mockCollaborator1._id, mockCollaborator2._id, mockCollaborator3._id);
  mockLab.services.push(mockService1._id, mockService2._id, mockService3._id);
  mockLab.inventory.push(mockInventory1._id, mockInventory2._id, mockInventory3._id);
  mockLab.orders.push(
    mockOrder1._id,
    mockOrder2._id,
    mockOrder3._id,
    mockOrder4._id,
    mockOrder5._id,
    mockOrder6._id,
    mockOrder7._id,
    mockOrder8._id,
    mockOrder9._id
  );
  mockLab.revenue[0].clinic = mockClinic1._id;
  mockLab.revenue[0].collaborator = mockCollaborator1._id;
  mockLab.revenue[1].clinic = mockClinic2._id;
  mockLab.revenue[1].collaborator = mockCollaborator2._id;
  mockLab.revenue[2].clinic = mockClinic3._id;
  mockLab.revenue[2].collaborator = mockCollaborator3._id;

  mockClinic1.orders.push(mockOrder1._id, mockOrder2._id, mockOrder3._id);
  mockClinic1.lab = mockLab._id;
  mockClinic1.balance[0].order = mockOrder1._id;
  mockClinic1.balance[1].order = mockOrder2._id;
  mockClinic1.balance[2].order = mockOrder3._id;
  mockClinic1.balance[0].service = mockOrder1.services[0]._id;
  mockClinic1.balance[1].service = mockOrder2.services[0]._id;
  mockClinic1.balance[2].service = mockOrder3.services[0]._id;

  mockClinic2.orders.push(mockOrder4._id, mockOrder5._id, mockOrder6._id);
  mockClinic2.lab = mockLab._id;
  mockClinic2.balance[0].order = mockOrder4._id;
  mockClinic2.balance[1].order = mockOrder5._id;
  mockClinic2.balance[2].order = mockOrder6._id;
  mockClinic2.balance[0].service = mockOrder4.services[0]._id;
  mockClinic2.balance[1].service = mockOrder5.services[0]._id;
  mockClinic2.balance[2].service = mockOrder6.services[0]._id;

  mockClinic3.orders.push(mockOrder7._id, mockOrder8._id, mockOrder9._id);
  mockClinic3.lab = mockLab._id;
  mockClinic3.balance[0].order = mockOrder7._id;
  mockClinic3.balance[1].order = mockOrder8._id;
  mockClinic3.balance[2].order = mockOrder9._id;
  mockClinic3.balance[0].service = mockOrder7.services[0]._id;
  mockClinic3.balance[1].service = mockOrder8.services[0]._id;
  mockClinic3.balance[2].service = mockOrder9.services[0]._id;

  mockCollaborator1.lab = mockLab._id;
  mockCollaborator2.lab = mockLab._id;
  mockCollaborator3.lab = mockLab._id;

  mockOrder1.clinic = mockClinic1._id;
  mockOrder1.dentist = mockClinic1.dentists[0]._id;
  mockOrder1.lab = mockLab._id;
  mockOrder1.patient = mockClinic1.patients[0]._id;
  mockOrder1.services[0].collaborator = mockCollaborator1._id;
  mockOrder1.services[0].createdBy = mockUser1._id;
  mockOrder1.services[1].collaborator = mockCollaborator2._id;
  mockOrder1.services[1].createdBy = mockUser2._id;
  mockOrder1.services[2].collaborator = mockCollaborator3._id;
  mockOrder1.services[2].createdBy = mockUser3._id;
  mockOrder1.comments[0].createdBy = mockUser1._id;

  mockOrder2.clinic = mockClinic1._id;
  mockOrder2.dentist = mockClinic1.dentists[1]._id;
  mockOrder2.lab = mockLab._id;
  mockOrder2.patient = mockClinic1.patients[1]._id;
  mockOrder2.services[0].collaborator = mockCollaborator1._id;
  mockOrder2.services[0].createdBy = mockUser1._id;
  mockOrder2.services[1].collaborator = mockCollaborator2._id;
  mockOrder2.services[1].createdBy = mockUser2._id;
  mockOrder2.services[2].collaborator = mockCollaborator3._id;
  mockOrder2.services[2].createdBy = mockUser3._id;
  mockOrder2.comments[0].createdBy = mockUser1._id;

  mockOrder3.clinic = mockClinic1._id;
  mockOrder3.dentist = mockClinic1.dentists[2]._id;
  mockOrder3.lab = mockLab._id;
  mockOrder3.patient = mockClinic1.patients[2]._id;
  mockOrder3.services[0].collaborator = mockCollaborator1._id;
  mockOrder3.services[0].createdBy = mockUser1._id;
  mockOrder3.services[1].collaborator = mockCollaborator2._id;
  mockOrder3.services[1].createdBy = mockUser2._id;
  mockOrder3.services[2].collaborator = mockCollaborator3._id;
  mockOrder3.services[2].createdBy = mockUser3._id;
  mockOrder3.comments[0].createdBy = mockUser1._id;

  mockOrder4.clinic = mockClinic2._id;
  mockOrder4.dentist = mockClinic2.dentists[0]._id;
  mockOrder4.lab = mockLab._id;
  mockOrder4.patient = mockClinic2.patients[0]._id;
  mockOrder4.services[0].collaborator = mockCollaborator1._id;
  mockOrder4.services[0].createdBy = mockUser1._id;
  mockOrder4.services[1].collaborator = mockCollaborator2._id;
  mockOrder4.services[1].createdBy = mockUser2._id;
  mockOrder4.services[2].collaborator = mockCollaborator3._id;
  mockOrder4.services[2].createdBy = mockUser3._id;
  mockOrder4.comments[0].createdBy = mockUser1._id;

  mockOrder5.clinic = mockClinic2._id;
  mockOrder5.dentist = mockClinic2.dentists[1]._id;
  mockOrder5.lab = mockLab._id;
  mockOrder5.patient = mockClinic2.patients[1]._id;
  mockOrder5.services[0].collaborator = mockCollaborator1._id;
  mockOrder5.services[0].createdBy = mockUser1._id;
  mockOrder5.services[1].collaborator = mockCollaborator2._id;
  mockOrder5.services[1].createdBy = mockUser2._id;
  mockOrder5.services[2].collaborator = mockCollaborator3._id;
  mockOrder5.services[2].createdBy = mockUser3._id;
  mockOrder5.comments[0].createdBy = mockUser1._id;

  mockOrder6.clinic = mockClinic2._id;
  mockOrder6.dentist = mockClinic2.dentists[2]._id;
  mockOrder6.lab = mockLab._id;
  mockOrder6.patient = mockClinic2.patients[2]._id;
  mockOrder6.services[0].collaborator = mockCollaborator1._id;
  mockOrder6.services[0].createdBy = mockUser1._id;
  mockOrder6.services[1].collaborator = mockCollaborator2._id;
  mockOrder6.services[1].createdBy = mockUser2._id;
  mockOrder6.services[2].collaborator = mockCollaborator3._id;
  mockOrder6.services[2].createdBy = mockUser3._id;
  mockOrder6.comments[0].createdBy = mockUser1._id;

  mockOrder7.clinic = mockClinic3._id;
  mockOrder7.dentist = mockClinic3.dentists[0]._id;
  mockOrder7.lab = mockLab._id;
  mockOrder7.patient = mockClinic3.patients[0]._id;
  mockOrder7.services[0].collaborator = mockCollaborator1._id;
  mockOrder7.services[0].createdBy = mockUser1._id;
  mockOrder7.services[1].collaborator = mockCollaborator2._id;
  mockOrder7.services[1].createdBy = mockUser2._id;
  mockOrder7.services[2].collaborator = mockCollaborator3._id;
  mockOrder7.services[2].createdBy = mockUser3._id;
  mockOrder7.comments[0].createdBy = mockUser1._id;

  mockOrder8.clinic = mockClinic3._id;
  mockOrder8.dentist = mockClinic3.dentists[1]._id;
  mockOrder8.lab = mockLab._id;
  mockOrder8.patient = mockClinic3.patients[1]._id;
  mockOrder8.services[0].collaborator = mockCollaborator1._id;
  mockOrder8.services[0].createdBy = mockUser1._id;
  mockOrder8.services[1].collaborator = mockCollaborator2._id;
  mockOrder8.services[1].createdBy = mockUser2._id;
  mockOrder8.services[2].collaborator = mockCollaborator3._id;
  mockOrder8.services[2].createdBy = mockUser3._id;
  mockOrder8.comments[0].createdBy = mockUser1._id;

  mockOrder9.clinic = mockClinic3._id;
  mockOrder9.dentist = mockClinic3.dentists[2]._id;
  mockOrder9.lab = mockLab._id;
  mockOrder9.services[0].collaborator = mockCollaborator1._id;
  mockOrder9.services[0].createdBy = mockUser1._id;
  mockOrder9.services[1].collaborator = mockCollaborator2._id;
  mockOrder9.services[1].createdBy = mockUser2._id;
  mockOrder9.services[2].collaborator = mockCollaborator3._id;
  mockOrder9.services[2].createdBy = mockUser3._id;
  mockOrder9.comments[0].createdBy = mockUser1._id;

  mockService1.lab = mockLab._id;
  mockService2.lab = mockLab._id;
  mockService3.lab = mockLab._id;

  mockInventory1.lab = mockLab._id;
  mockInventory2.lab = mockLab._id;
  mockInventory3.lab = mockLab._id;

  return [
    [
      mockLab
    ],
    [
      mockClinic1,
      mockClinic2,
      mockClinic3
    ],
    [
      mockCollaborator1,
      mockCollaborator2,
      mockCollaborator3
    ],
    [
      mockOrder1,
      mockOrder2,
      mockOrder3,
      mockOrder4,
      mockOrder5,
      mockOrder6,
      mockOrder7,
      mockOrder8,
      mockOrder9
    ],
    [
      mockUser1,
      mockUser2,
      mockUser3
    ],
    [
      mockService1,
      mockService2,
      mockService3
    ],
    [
      mockInventory1,
      mockInventory2,
      mockInventory3
    ]
  ];
}

const testDocuments = (modelArray, modelMockData) => {
  modelArray.map(
    (model, index) => {
      modelMockData[index].map(
        (data) => {
          const document = new model(data);
          const testResult = document.validateSync();
          if (testResult) {
            logger.log(`${model.modelName}: ${testResult}`);
          }
        }
      );
    }
  );
}

const saveDocuments = async (modelArray, modelMockData) => {
  try {
    await Promise.all(
      modelArray.map(
        (model, index) => {
          return Promise.all(
            modelMockData[index].map(
              (data) => {
                const document = new model(data);
                return document.save();
              }
            )
          );
        }
      )
    );
  } catch (err) {
    logger.error(err);
  }
}

initDB();
// TODO: figure out what to do with Panda Scan