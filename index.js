var express = require('express');
var bodyParser = require('body-parser');
var FileAuthDB = require('./src/FileAuthDB');
var JWT = require('./src/JWT');

/**
 * Wrap a function returning a promise (such as async functions)
 * so that its exceptions are handled
 */
let wrapAsync = fn => (...args) => fn(...args).catch(args[2]);

let jwtVerifyOptions = {
  algorithms: 'HS256'
};

class SaintPeter {
  constructor (config, logger) {
    this.config = config;
    if (logger) {
      this.logger = logger;
    } else {
      this.logger = console;
    }
    switch (String(config.dbType)) {
      case (String('file')):
        this.authDB = new FileAuthDB(config);
        break;
      default:
        // TODO: handle default case
        this.authDB = new FileAuthDB({filename: './auth.json'});
    }
  }

  authenticate () {
    let router = express.Router();
    router.use(bodyParser.json(), this.authenticateParsedRequest());
    return router;
  }

  authenticateParsedRequest () {
    return wrapAsync(async (req, res) => {
      let username = req.body.username;
      let password = req.body.password;
      try {
        let success = await this.authDB.authenticateUser(username, password);
        if (!success) {
          // invalid username or password. all other errors should throw
          // an exception and are catched by the next block
          res.status(401).json({
            success: false
          });
          return;
        }
      } catch (e) {
        // some error occurred while authenticating the user
        this.logger.error(e.message);
        return res.status(401).json({
          success: false
        });
      }

      let groups = await this.authDB.getUserGroups(username);
      let token = await JWT.encodeToken({
        exp: Math.floor(Date.now() / 1000) + (60 * 60),
        username: username,
        groups: groups
      }, this.config.jwtSecret, {algorithm: 'HS256'});

      res.json({
        success: true,
        token: token
      });
    });
  }

  /**
   *
   */
  requireAuthentication () {
    let router = express.Router();
    router.use(wrapAsync(async (req, res, next) => {
      try {
        await JWT.decodeToken(req, this.config.jwtSecret, jwtVerifyOptions);
        next();
      } catch (e) {
        res.status(403).json({
          success: false,
          message: 'Forbidden'
        });
      }
    }));
    return router;
  }

  allowUsers (users) {
    return wrapAsync(async (req, res, next) => {
      try {
        let decodedToken = await JWT.decodeToken(req, this.config.jwtSecret, jwtVerifyOptions);
        if (users.indexOf(decodedToken.username) < 0) {
          throw new Error('Forbidden');
        }
        next();
      } catch (e) {
        res.status(403).json({
          success: false,
          message: 'Forbidden'
        });
      }
    });
  }

  allowGroups (groups) {
    return wrapAsync(async (req, res, next) => {
      try {
        let decodedToken = await JWT.decodeToken(req, this.config.jwtSecret, jwtVerifyOptions);
        let groups = await this.authDB.getGroups();
        if (!('groups' in decodedToken)) {
          throw new Error('No groups in token');
        }
        for (let tokenGroup of decodedToken.groups) {
          if (groups.indexOf(tokenGroup) >= 0) {
            return next();
          }
        }
        // the token might be outdated, try to fetch the groups against
        let userGroups = await this.authDB.getUserGroups(decodedToken.username);
        for (let tokenGroup of userGroups) {
          if (groups.indexOf(tokenGroup) >= 0) {
            return next();
          }
        }
        throw new Error('Forbidden');
      } catch (e) {
        res.status(403).json({
          success: false,
          message: 'Forbidden'
        });
      }
    });
  }

  getUsers () {
    let router = express.Router();
    router.use(wrapAsync(async (req, res) => {
      res.send(await this.authDB.getUsers());
    }));
    return router;
  }

  getGroups () {
    let router = express.Router();
    router.use(wrapAsync(async (req, res) => {
      res.send(await this.authDB.getGroups());
    }));
    return router;
  }

  addUser () {
    let router = express.Router();
    router.use(bodyParser.json(), wrapAsync(async (req, res) => {
      let success = await this.authDB.addUser(req.body.username, req.body.password);
      res.status(success ? 200 : 409).json({
        success: success
      });
    }));
    return router;
  }

  deleteUser () {
    let router = express.Router();
    router.use(bodyParser.json(), wrapAsync(async (req, res) => {
      let success = await this.authDB.deleteUser(req.body.username);
      res.status(success ? 200 : 409).json({
        success: success
      });
    }));
    return router;
  }

  addGroup () {
    let router = express.Router();
    router.use(bodyParser.json(), wrapAsync(async (req, res) => {
      let success = await this.authDB.addGroup(req.body.group);
      res.status(success ? 200 : 409).json({
        success: success
      });
    }));
    return router;
  }

  deleteGroup () {
    let router = express.Router();
    router.use(bodyParser.json(), wrapAsync(async (req, res) => {
      let success = await this.authDB.deleteGroup(req.body.group);
      res.status(success ? 200 : 409).json({
        success: success
      });
    }));
    return router;
  }

  addUserToGroup () {
    let router = express.Router();
    router.use(bodyParser.json(), wrapAsync(async (req, res) => {
      let success = await this.authDB.addUserToGroup(req.body.username, req.body.group);
      res.status(success ? 200 : 409).json({
        success: success
      });
    }));
    return router;
  }

  removeUserFromGroup () {
    let router = express.Router();
    router.use(bodyParser.json(), wrapAsync(async (req, res) => {
      let success = await this.authDB.removeUserFromGroup(req.body.username, req.body.group);
      res.status(success ? 200 : 409).json({
        success: success
      });
    }));
    return router;
  }
}

module.exports = SaintPeter;
