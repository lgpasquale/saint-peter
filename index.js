var express = require('express');
var bodyParser = require('body-parser');
var FileAuthDB = require('./src/FileAuthDB');
var jwt = require('./src/jwt');

/**
 * Wrap a function returning a promise (such as async functions)
 * so that its exceptions are handled
 */
let wrapAsync = fn => (...args) => fn(...args).catch(args[2]);

let jwtVerifyOptions = {
  algorithms: 'HS256'
};

class SaintPeter {
  /**
   * @param config an object containing the following fields:
   * - dbType: one of mariadb, sqlite, file
   * - defaultUsername: user created if auth db is empty
   * - defaultPassword: password assigned to the default user
   * - defaultGroup: group assigned to the default user
   * - tokenLifetime: validity period of generated tokens
   * - tokenIdleTimeout: how long after a token has expired it can be renewed
   * @param logger a logger that should provide the methods info and error.
   * Defaults to console
   */
  constructor (config, logger) {
    this.config = config;
    if (logger) {
      this.logger = logger;
    } else {
      this.logger = console;
    }
    // fill in missing config parameters
    if (typeof this.config.dbType === 'undefined') {
      this.config.dbType = 'file';
    }
    if (typeof this.config.defaultUsername === 'undefined') {
      this.config.defaultUsername = 'admin';
    }
    if (typeof this.config.defaultPassword === 'undefined') {
      this.config.defaultPassword = 'admin';
    }
    if (typeof this.config.defaultGroup === 'undefined') {
      this.config.defaultGroup = 'admin';
    }
    if (typeof this.config.tokenLifetime === 'undefined') {
      this.config.tokenLifetime = 60 * 60;
    }
    if (typeof this.config.tokenIdleTimeout === 'undefined') {
      this.config.tokenIdleTimeout = 60 * 60;
    }
    // instantiate the db backend
    switch (String(this.config.dbType)) {
      case (String('file')):
        this.authDB = new FileAuthDB(this.config);
        break;
      default:
        // TODO: handle default case
        this.authDB = new FileAuthDB({filename: './auth.json'});
    }
    // populate the db (if empty) with default user and group
    this.initializeDB().catch((e) => {
      this.logger.error(e.message);
    });
  }

  /**
   * If there are no users in the DB, create the default user
   * The default user is created with a default password and added to a
   * default group (which is created if it doesn't already exist)
   */
  async initializeDB () {
    let defaultUsername = this.config.defaultUsername;
    let defaultPassword = this.config.defaultPassword;
    let defaultGroup = this.config.defaultGroup;
    let users = await this.authDB.getUsers();
    if (users.length <= 0) {
      this.logger.info('Creating default user \'' + defaultUsername +
        '\' with password \'' + defaultPassword + '\'');
      await this.authDB.addUser(defaultUsername, defaultPassword);
      let groups = await this.authDB.getGroups();
      if (groups.indexOf(defaultGroup) < 0) {
        this.logger.info('Creating default group \'' + defaultGroup + '\'');
        await this.authDB.addGroup(defaultGroup);
      }
      this.logger.info('Adding user \'' + defaultUsername + '\' to group \'' +
        defaultGroup + '\'');
      await this.authDB.addUserToGroup(defaultUsername, defaultGroup);
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
      let email = await this.authDB.getUserEmail(username);
      let firstName = await this.authDB.getUserFirstName(username);
      let lastName = await this.authDB.getUserLastName(username);
      let expirationDate = Math.floor(Date.now() / 1000) + (60 * 60);
      let renewalExpirationDate = expirationDate + 60 * 60;
      let token = await jwt.encodeToken({
        exp: expirationDate,
        renewalExpirationDate: renewalExpirationDate,
        username: username,
        groups: groups,
        email: email,
        firstName: firstName,
        lastName: lastName
      }, this.config.jwtSecret, {algorithm: 'HS256'});

      res.json({
        success: true,
        token: token,
        username: username,
        groups: groups,
        email: email,
        firstName: firstName,
        lastName: lastName,
        tokenExpirationDate: expirationDate
      });
    });
  }

  renewToken () {
    let router = express.Router();
    router.use(bodyParser.json(), this.renewTokenParsedRequest());
    return router;
  }

  renewTokenParsedRequest () {
    return wrapAsync(async (req, res) => {
      try {
        let decodedOldToken = await jwt.decodeTokenHeader(req, this.config.jwtSecret,
          Object.assign({}, jwtVerifyOptions, {ignoreExpiration: true}));
        console.log(decodedOldToken.renewalExpirationDate,
        (new Date()).getTime() / 1000);
        if (decodedOldToken.renewalExpirationDate < (new Date()).getTime() / 1000) {
          throw new Error('Expired token');
        }

        let username = decodedOldToken.username;
        // we could get the groups from the token, but we take this chance toupdate them
        let groups = await this.authDB.getUserGroups(username);
        let email = await this.authDB.getUserEmail(username);
        let firstName = await this.authDB.getUserFirstName(username);
        let lastName = await this.authDB.getUserLastName(username);
        let expirationDate = Math.floor(Date.now() / 1000) +
          this.config.tokenLifetime;
        let renewalExpirationDate = expirationDate +
          this.config.tokenIdleTimeout;
        let token = await jwt.encodeToken({
          exp: expirationDate,
          renewalExpirationDate: renewalExpirationDate,
          username: username,
          groups: groups,
          email: email,
          firstName: firstName,
          lastName: lastName
        }, this.config.jwtSecret, {algorithm: 'HS256'});

        res.json({
          success: true,
          token: token,
          username: username,
          groups: groups,
          email: email,
          firstName: firstName,
          lastName: lastName,
          tokenExpirationDate: expirationDate
        });
      } catch (e) {
        console.log(e.message);
        res.status(401).json({
          success: false,
          message: 'Expired token'
        });
      }
    });
  }

  /**
   *
   */
  requireAuthentication () {
    let router = express.Router();
    router.use(wrapAsync(async (req, res, next) => {
      try {
        await jwt.decodeTokenHeader(req, this.config.jwtSecret, jwtVerifyOptions);
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
        let decodedToken = await jwt.decodeTokenHeader(req, this.config.jwtSecret, jwtVerifyOptions);
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
        let decodedToken = await jwt.decodeTokenHeader(req, this.config.jwtSecret, jwtVerifyOptions);
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
      res.json(await this.authDB.getUsers());
    }));
    return router;
  }

  getGroups () {
    let router = express.Router();
    router.use(wrapAsync(async (req, res) => {
      res.json(await this.authDB.getGroups());
    }));
    return router;
  }

  addUser () {
    let router = express.Router();
    router.use(bodyParser.json(), wrapAsync(async (req, res) => {
      let success = true;
      try {
        success = await this.authDB.addUser(req.body.username, req.body.password);
      } catch (e) {
        this.logger.error(e.message);
        success = false;
      }
      res.status(success ? 200 : 409).json({
        success: success
      });
    }));
    return router;
  }

  deleteUser () {
    let router = express.Router();
    router.use(bodyParser.json(), wrapAsync(async (req, res) => {
      let success = true;
      try {
        success = await this.authDB.deleteUser(req.body.username);
      } catch (e) {
        success = false;
        this.logger.error(e.message);
      }
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

  setUserPassword () {
    let router = express.Router();
    router.use(bodyParser.json(), wrapAsync(async (req, res) => {
      let username = req.body.username;
      let oldPassword = req.body.oldPassword;
      let newPassword = req.body.newPassword;
      try {
        let success = await this.authDB.authenticateUser(username, oldPassword);
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

      let success = true;
      try {
        await this.authDB.setUserPassword(username, newPassword);
      } catch (e) {
        success = false;
      }
      res.status(success ? 200 : 409).json({
        success: success
      });
    }));
    return router;
  }

  setUserEmail () {
    let router = express.Router();
    router.use(bodyParser.json(), wrapAsync(async (req, res) => {
      let success = true;
      try {
        await this.authDB.setUserEmail(req.body.username, req.body.email);
      } catch (e) {
        success = false;
      }
      res.status(success ? 200 : 409).json({
        success: success
      });
    }));
    return router;
  }

  getUsersInfo () {
    let router = express.Router();
    router.use(wrapAsync(async (req, res) => {
      let success = true;
      let usersInfo = {};
      try {
        let users = await this.authDB.getUsers();
        for (let username of users) {
          usersInfo[username] = {};
          usersInfo[username].username = username;
          usersInfo[username].email = await this.authDB.getUserEmail(username);
          usersInfo[username].firstName = await this.authDB.getUserFirstName(username);
          usersInfo[username].lastName = await this.authDB.getUserLastName(username);
          usersInfo[username].groups = await this.authDB.getUserGroups(username);
        }
      } catch (e) {
        success = false;
      }
      res.status(success ? 200 : 409).json(usersInfo);
    }));
    return router;
  }
}

module.exports = SaintPeter;
