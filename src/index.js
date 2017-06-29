var express = require('express');
var bodyParser = require('body-parser');
var FileAuthDB = require('./FileAuthDB');
var SQLAuthDB = require('./SQLAuthDB');
var jwt = require('./jwt');

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
    // jwtSecret is mandatory (we don't want to provide a default one)
    if (!this.config.jwtSecret) {
      throw new Error('No jwtSecret provided in config');
    }
    // fill in missing config parameters
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
    } else {
      this.config.tokenLifetime = Number(this.config.tokenLifetime);
    }
    if (typeof this.config.tokenIdleTimeout === 'undefined') {
      this.config.tokenIdleTimeout = 60 * 60;
    } else {
      this.config.tokenIdleTimeout = Number(this.config.tokenIdleTimeout);
    }
    // instantiate the db backend
    if (this.config.dbType) {
      switch (String(this.config.dbType)) {
        case 'sqlite':
        case 'mysql':
        case 'mariadb':
        case 'postgresql':
          this.authDB = new SQLAuthDB(this.config);
          break;
        case (String('file')):
          this.authDB = new FileAuthDB(this.config);
          break;
        default:
          this.authDB = new SQLAuthDB({
            dbType: 'sqlite',
            storage: 'authdb.sqlite'
          });
      }
    }
  }

  /**
   * If there are no users in the DB, create the default user
   * The default user is created with a default password and added to a
   * default group (which is created if it doesn't already exist)
   */
  async initializeDB () {
    // Create tables if they don't exist
    this.authDB.initialize();
    // Create default user if none exist
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
    router.post('/', bodyParser.json(), this.authenticateParsedRequest());
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
    });
  }

  renewToken () {
    let router = express.Router();
    router.post('/', bodyParser.json(), this.renewTokenParsedRequest());
    return router;
  }

  renewTokenParsedRequest () {
    return wrapAsync(async (req, res) => {
      try {
        let decodedOldToken = await jwt.decodeTokenHeader(req, this.config.jwtSecret,
          Object.assign({}, jwtVerifyOptions, {ignoreExpiration: true}));
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
    return wrapAsync(async (req, res, next) => {
      try {
        await jwt.decodeTokenHeader(req, this.config.jwtSecret, jwtVerifyOptions);
        next();
      } catch (e) {
        res.status(403).json({
          success: false,
          message: 'Forbidden'
        });
      }
    });
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
        if (!('groups' in decodedToken)) {
          throw new Error('No groups in token');
        }
        for (let tokenGroup of decodedToken.groups) {
          if (groups.indexOf(tokenGroup) >= 0) {
            return next();
          }
        }
        // the token might be outdated, try to fetch groups from the db
        if (this.authDB) {
          let userGroups = await this.authDB.getUserGroups(decodedToken.username);
          for (let tokenGroup of userGroups) {
            if (groups.indexOf(tokenGroup) >= 0) {
              return next();
            }
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

  getUsernames () {
    let router = express.Router();
    router.get('/', wrapAsync(async (req, res) => {
      res.json(await this.authDB.getUsernames());
    }));
    return router;
  }

  getUsers () {
    let router = express.Router();
    router.get('/', wrapAsync(async (req, res) => {
      let success = true;
      let users = {};
      try {
        users = await this.authDB.getUsers();
      } catch (e) {
        success = false;
      }
      res.status(success ? 200 : 409).json(users);
    }));
    return router;
  }

  getGroups () {
    let router = express.Router();
    router.get('/', wrapAsync(async (req, res) => {
      res.json(await this.authDB.getGroups());
    }));
    return router;
  }

  addUser () {
    let router = express.Router();
    router.post('/', bodyParser.json(), wrapAsync(async (req, res) => {
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
    router.delete('/:username', wrapAsync(async (req, res) => {
      let success = true;
      try {
        success = await this.authDB.deleteUser(req.params.username);
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
    router.post('/', bodyParser.json(), wrapAsync(async (req, res) => {
      let success = await this.authDB.addGroup(req.body.group);
      res.status(success ? 200 : 409).json({
        success: success
      });
    }));
    return router;
  }

  deleteGroup () {
    let router = express.Router();
    router.delete('/:group', wrapAsync(async (req, res) => {
      let success = await this.authDB.deleteGroup(req.params.group);
      res.status(success ? 200 : 409).json({
        success: success
      });
    }));
    return router;
  }

  addUserToGroup () {
    let router = express.Router();
    router.post('/:username/groups', bodyParser.json(), wrapAsync(async (req, res) => {
      let success = await this.authDB.addUserToGroup(req.params.username, req.body.group);
      res.status(success ? 200 : 409).json({
        success: success
      });
    }));
    return router;
  }

  removeUserFromGroup () {
    let router = express.Router();
    router.delete('/:username/groups/:group', wrapAsync(async (req, res) => {
      let success = await this.authDB.removeUserFromGroup(req.params.username, req.params.group);
      res.status(success ? 200 : 409).json({
        success: success
      });
    }));
    return router;
  }

  setUserPassword () {
    let router = express.Router();
    router.put('/:username/password', bodyParser.json(), wrapAsync(async (req, res) => {
      let username = req.params.username;
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

  resetUserPassword () {
    let router = express.Router();
    router.post('/:username/reset-password', bodyParser.json(), wrapAsync(async (req, res) => {
      let username = req.params.username;
      let password = req.body.password;

      let success = true;
      try {
        await this.authDB.setUserPassword(username, password);
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
    router.put('/:username/email', bodyParser.json(), wrapAsync(async (req, res) => {
      let success = true;
      try {
        let decodedToken = await jwt.decodeTokenHeader(req, this.config.jwtSecret, jwtVerifyOptions);
        if (decodedToken.username !== req.params.username) {
          // the user making the request has to match the user whose password
          // we are trying to change
          throw new Error('Forbidden');
        }
        await this.authDB.setUserEmail(req.params.username, req.body.email);
      } catch (e) {
        success = false;
      }
      res.status(success ? 200 : 409).json({
        success: success
      });
    }));
    return router;
  }

  setUserInfo () {
    let router = express.Router();
    router.patch('/:username', bodyParser.json(), wrapAsync(async (req, res) => {
      let success = true;
      let username = req.params.username;
      try {
        if (username !== req.body.username) {
          await this.authDB.renameUser(username, req.body.username);
          username = req.body.username;
        }
        if (req.body.firstName) {
          await this.authDB.setUserFirstName(username, req.body.firstName);
        }
        if (req.body.lastName) {
          await this.authDB.setUserLastName(username, req.body.lastName);
        }
        if (req.body.email) {
          await this.authDB.setUserEmail(username, req.body.email);
        }
        if (req.body.groups) {
          await this.authDB.setUserGroups(username, req.body.groups);
        }
      } catch (e) {
        success = false;
      }
      res.status(success ? 200 : 409).json({
        success: success
      });
    }));
    return router;
  }

  defaultRouters (adminGroups = ['admin']) {
    let router = express.Router();
    router.use('/authenticate', this.authenticate());
    router.use('/renew-token', this.renewToken());
    router.use('/users', this.allowGroups(adminGroups), this.addUser());
    router.use('/users', this.allowGroups(adminGroups), this.deleteUser());
    router.use('/groups', this.allowGroups(adminGroups), this.addGroup());
    router.use('/groups', this.allowGroups(adminGroups), this.deleteGroup());
    router.use('/users', this.allowGroups(adminGroups), this.addUserToGroup());
    router.use('/users', this.allowGroups(adminGroups), this.removeUserFromGroup());
    router.use('/users', this.setUserEmail());
    router.use('/users', this.setUserPassword());
    router.use('/users', this.allowGroups(adminGroups), this.resetUserPassword());
    router.use('/users', this.allowGroups(adminGroups), this.setUserInfo());
    router.use('/users', this.allowGroups(adminGroups), this.getUsers());
    router.use('/usernames', this.allowGroups(adminGroups), this.getUsernames());
    router.use('/groups', this.allowGroups(adminGroups), this.getGroups());
    return router;
  }
}

module.exports = SaintPeter;
