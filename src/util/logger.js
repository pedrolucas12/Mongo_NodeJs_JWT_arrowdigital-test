/* eslint-disable no-console */
import chalk from 'chalk';
import moment from 'moment';
import path from 'path';
import { fileURLToPath } from 'url';
import fs from 'fs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
if (!fs.existsSync(path.join(__dirname, '../data/local/local.log'))) {
  fs.writeFileSync(path.join(__dirname, '../data/local/local.log'), '');
}
// TODO: cloudwatch implementation

class Logger {
  constructor() {
    // TODO: implement logger state for each module
    this.state = null;
    this.log = (content, type = 'log') => {
      const stream = fs.createWriteStream(path.join(__dirname, '../data/local/local.log'), {
        flags: 'a'
      });
      const timestamp = `[${moment().format('YYYY-MM-DD HH:mm:ss')}]:`;
      const logged = `${timestamp} ${content} `;
      switch (type) {
        case 'log': {
          stream.write(`${logged}\n`);
          stream.end();
          return console.log(chalk.bgBlue(type.toUpperCase()), logged);
        }
        case 'warn': {
          stream.write(`${logged}\n`);
          stream.end();
          return console.log(chalk.black.bgYellow(type.toUpperCase()), logged);
        }
        case 'error': {
          stream.write(`${logged}\n`);
          stream.end();
          return console.log(chalk.bgRed(type.toUpperCase()), logged);
        }
        case 'debug': {
          stream.write(`${logged}\n`);
          stream.end();
          return console.log(chalk.green(type.toUpperCase()), logged);
        }
        case 'cmd': {
          stream.write(`${logged}\n`);
          stream.end();
          return console.log(chalk.black.bgWhite(type.toUpperCase()), logged);
        }
        case 'ready': {
          stream.write(`${logged}\n`);
          stream.end();
          return console.log(chalk.black.bgGreen(type.toUpperCase()), logged);
        }
        default:
          throw new TypeError('Logger type must be either warn, debug, log, ready, cmd or error.');
      }
    };
  };

  log = (...args) => this.log(...args, 'log');

  error = (...args) => this.log(...args, 'error');

  warn = (...args) => this.log(...args, 'warn');
  
  debug = (...args) => this.log(...args, 'debug');
  
  cmd = (...args) => this.log(...args, 'cmd');
  
  ready = (...args) => this.log(...args, 'ready');
}

export default new Logger();