#!/usr/bin/env node

var express = require('express');
// var bunyan = require('bunyan');
var SaintPeter = require('./index');

const argv = require('yargs')
  .option('address', {
    alias: 'a',
    describe: 'address the server will listen on',
    default: '0.0.0.0'
  })
  .option('port', {
    alias: 'p',
    describe: 'port the server will listen on',
    default: 3000
  })
  .option('db', {
    describe: 'database URL',
    default: 'sqlite://auth.sqlite'
  })
  .option('secret', {
    describe: 'secret used to generate the JSON Web Token'
  })
  .help()
  .argv;

var saintPeterOptions = {
  jwtSecret: argv.secret,
  dbURI: argv.db
};

let saintPeter = new SaintPeter(saintPeterOptions);

// var log = bunyan.createLogger({
//   name: 'app',
//   streams: [{
//     type: 'rotating-file',
//     level: 'info',
//     path: './server.log',
//     period: '1m', // monthly rotation
//     count: 3 // keep 3 back copies
//   },
//     {
//       level: 'info',
//       stream: process.stdout // log INFO and above to stdout
//     }],
//   serializers: bunyan.stdSerializers
// });
let log = console;

var app = express();

// Log all requests
app.use('/', function (req, res, next) {
  log.info({'req': req});
  next();
});

// Setup default routers
app.use('/', saintPeter.defaultRouters(['admin']));

log.info('Initializing DB...');
saintPeter.initializeDB().then(() =>
  app.listen(Number(argv.port), argv.address, function () {
    log.info('Listening on http://' + argv.address + ':' + argv.port);
  })
).catch((e) => console.log(e.stack));
