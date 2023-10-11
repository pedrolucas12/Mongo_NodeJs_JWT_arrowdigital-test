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
import m2s from 'mongoose-to-swagger';
import path from 'path';
import { fileURLToPath } from 'url';
import fs from 'fs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
if (!fs.existsSync(path.join(__dirname, '../public/models.json'))) {
  fs.writeFileSync(path.join(__dirname, '../public/models.json'), '');
}
// TODO: cloud implementation

// transform models to swagger and save to file
const generateSwagger = () => {
    const clinicSwagger =  m2s(Clinic);
    const collaboratorSwagger = m2s(Collaborator);
    const labSwagger = m2s(Lab);
    const orderSwagger = m2s(Order);
    const userSwagger = m2s(User);
    const pandaScanSwagger = m2s(PandaScan);
    const serviceSwagger = m2s(Service);
    const inventorySwagger = m2s(Inventory);
    const swagger = {
        Clinic: clinicSwagger,
        Collaborator: collaboratorSwagger,
        Lab: labSwagger,
        Order: orderSwagger,
        User: userSwagger,
        PandaScan: pandaScanSwagger,
        Service: serviceSwagger,
        Inventory: inventorySwagger
    };
 
    fs.writeFileSync(path.join(__dirname, '../public/models.json'), JSON.stringify(swagger));
};

generateSwagger();