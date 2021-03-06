#!/usr/bin/env node

var express = require('express');
var cors = require('cors');
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
  .option('issuer', {
    alias: 'iss',
    describe: 'token issuer (iss field of the jwt)',
    default: ''
  })
  .option('root-path', {
    alias: 'r',
    describe: 'root path; the API will be available as subpaths of this',
    default: '/'
  })
  .option('token-lifetime', {
    describe: 'token lifetime in seconds',
    default: 3600
  })
  .option('token-idle-timeout', {
    describe: 'how long (in seconds) after a token has expired can it be ' +
      'renewed without having to authenticate again',
    default: 3600 * 24
  })
  .option('default-username', {
    describe: 'user created if no user is found',
    default: 'admin'
  })
  .option('default-password', {
    describe: 'password assigned to the default user',
    default: 'admin'
  })
  .option('default-group', {
    describe: 'group created if no group is found',
    default: 'admin'
  })
  .help()
  .argv;

var saintPeterOptions = {
  jwtSecret: argv.secret,
  dbURI: argv.db,
  issuer: argv.issuer,
  tokenLifetime: argv.tokenLifetime,
  tokenIdleTimeout: argv.tokenIdleTimeout,
  defaultUsername: argv.defaultUsername,
  defaultPassword: argv.defaultPassword,
  defaultGroup: argv.defaultGroup
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

// Enable CORS
app.use(cors());

// Log all requests
app.use(argv.rootPath, function (req, res, next) {
  log.info('[' + Date() + '] ' + req.method + ' ' + req.url + ' ' + req.ip);
  next();
});

// Setup default routers
app.use(argv.rootPath, saintPeter.defaultRouters(['admin']));

log.info('Initializing DB...');
saintPeter.initializeDB().then(() =>
  app.listen(Number(argv.port), argv.address, function () {
    log.info('Listening on http://' + argv.address + ':' + argv.port);
  })
).catch((e) => console.log(e.stack));
