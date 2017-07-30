var Sequelize = require('sequelize');
var PasswordHandler = require('./PasswordHandler');

class SQLAuthDB {
  constructor (config) {
    if (config.dbURI) {
      this.sequelize = new Sequelize(config.dbURI, {
        logging: false
      });
    } else if (config.dbType === 'sqlite') {
      this.sequelize = new Sequelize(config.database, null, null, {
        dialect: 'sqlite',
        storage: config.storage || './authdb/authdb.sqlite',
        logging: false
      });
    } else {
      this.sequelize = new Sequelize(config.database,
        config.username,
        config.password,
        {
          dialect: config.dbType || 'mysql',
          host: config.host || 'localhost',
          port: config.port || '3306',
          logging: false
        }
      );
    }

    // Define the models (i.e. the tables)
    this.User = this.sequelize.define('user', {
      id: {
        type: Sequelize.BIGINT,
        primaryKey: true,
        autoIncrement: true
      },
      username: {
        type: Sequelize.STRING,
        unique: true
      },
      email: {
        type: Sequelize.STRING
      },
      firstName: {
        type: Sequelize.STRING,
        field: 'first_name'
      },
      lastName: {
        type: Sequelize.STRING,
        field: 'last_name'
      },
      password: {
        type: Sequelize.STRING
      }
    }, {
      // don't forget to enable timestamps!
      timestamps: true,
      // I don't want createdAt
      createdAt: 'creation_timestamp',
      // I want updatedAt to actually be called updateTimestamp
      updatedAt: 'update_timestamp'
    });

    this.Group = this.sequelize.define('group', {
      id: {
        type: Sequelize.BIGINT,
        primaryKey: true,
        autoIncrement: true
      },
      groupname: {
        type: Sequelize.STRING,
        unique: true
      }
    }, {
      // don't forget to enable timestamps!
      timestamps: true,
      // I don't want createdAt
      createdAt: 'creation_timestamp',
      // I want updatedAt to actually be called updateTimestamp
      updatedAt: 'update_timestamp'
    });

    this.UserGroups = this.sequelize.define('user_groups', {
      id: {
        type: Sequelize.BIGINT,
        primaryKey: true,
        autoIncrement: true
      },
      username: {
        type: Sequelize.STRING,
        references: {
          // Reference to the other model
          model: this.User,
          // Column name of the referenced model
          key: 'username'
        },
        unique: 'userGroup'
      },
      groupname: {
        type: Sequelize.STRING,
        references: {
          // Reference to the other model
          model: this.Group,
          // Column name of the referenced model
          key: 'groupname'
        },
        unique: 'userGroup'
      }
    }, {
      // Model tableName will be the same as the model name
      freezeTableName: true,
      // don't forget to enable timestamps!
      timestamps: true,
      // I don't want createdAt
      createdAt: 'creation_timestamp',
      // I want updatedAt to actually be called updateTimestamp
      updatedAt: 'update_timestamp'
    });
  }

  async initialize () {
    await this.User.sync();
    await this.Group.sync();
    await this.UserGroups.sync();
  }

  async authenticateUser (username, password) {
    let user = await this.User.findOne({
      where: {username: username}
    });
    if (!user) {
      return false;
    }
    return await PasswordHandler.verifyPassword(password,
      user.password);
  }

  async getUserGroups (username) {
    let userGroups = await this.UserGroups.findAll({
      where: {username: username}
    });
    return userGroups.map((userGroup) => userGroup.groupname);
  }

  async getUserEmail (username) {
    let user = await this.User.findOne({
      attributes: ['email'],
      where: {username: username}
    });
    return user.email;
  }

  async getUserFirstName (username) {
    let user = await this.User.findOne({
      attributes: ['firstName'],
      where: {username: username}
    });
    return user.firstName;
  }

  async getUserLastName (username) {
    let user = await this.User.findOne({
      attributes: ['lastName'],
      where: {username: username}
    });
    return user.lastName;
  }

  async getUser (username) {
    let user = await this.User.findOne({
      attributes: ['id', 'username', 'email', 'firstName', 'lastName'],
      where: {username: username}
    });
    user = user.get();
    user.groups = await this.getUserGroups(username);
    return user;
  }

  async setUserGroups (username, groups) {
    let userGroups = await this.UserGroups.findAll({
      where: {username: username}
    });
    // Remove the user from groups not in the provided list
    for (let userGroup of userGroups) {
      if (groups.indexOf(userGroup.groupname) < 0) {
        // Remove the user from this group
        await this.UserGroups.destroy({
          where: {id: userGroup.id}
        });
      }
    }
    // Add the user to new groups
    for (let group of groups) {
      await this.UserGroups.findOrCreate({
        where: {
          username: username,
          groupname: group
        },
        defaults: {
          username: username,
          groupname: group
        }
      });
    }
  }

  async setUserEmail (username, email) {
    await this.User.update({email: email}, {
      where: {username: username}
    });
  }

  async setUserFirstName (username, firstName) {
    await this.User.update({firstName: firstName}, {
      where: {username: username}
    });
  }

  async setUserLastName (username, lastName) {
    await this.User.update({lastName: lastName}, {
      where: {username: username}
    });
  }

  async setUserPassword (username, password) {
    let combinedHash = await PasswordHandler.hashPassword(password);
    await this.User.update({password: combinedHash}, {
      where: {username: username}
    });
  }

  async getUsernames () {
    let users = await this.User.findAll({attributes: ['username']});
    return users.map((user) => user.username);
  }

  async getUsers () {
    let users = await this.User.findAll({
      attributes: ['id', 'username', 'email', 'firstName', 'lastName']
    });
    users = users.map((user) => user.get());
    for (let user of users) {
      user.groups = await this.getUserGroups(user.username);
    }
    return users;
  }

  async getGroups () {
    let groups = await this.Group.findAll({attributes: ['groupname']});
    return groups.map((group) => group.groupname);
  }

  async addUser (username, password) {
    try {
      let combinedHash = await PasswordHandler.hashPassword(password);
      await this.User.create({
        username: username,
        password: combinedHash,
        email: '',
        firstName: '',
        lastName: ''
      });
    } catch (e) {
      return false;
    }
    return true;
  }

  async deleteUser (username) {
    let user = await this.User.findOne({
      where: {username: username}
    });
    if (!user) {
      return false;
    }
    await this.User.destroy({
      where: {id: user.id}
    });
    return true;
  }

  async renameUser (username, newUsername) {
    let user = await this.User.findOne({
      where: {username: username}
    });
    if (!user) {
      throw new Error('Cannot rename user ' + username + 'because it doesn\'t exist');
    }
    await this.User.update({
      username: newUsername
    }, {
      where: {id: user.id}
    });
  }

  async addGroup (group) {
    try {
      await this.Group.create({
        groupname: group
      });
    } catch (e) {
      return false;
    }
    return true;
  }

  async deleteGroup (groupname) {
    let group = await this.Group.findOne({
      where: {groupname: groupname}
    });
    if (!groupname) {
      return false;
    }
    await this.Groups.destroy({
      where: {id: group.id}
    });
    return true;
  }

  async addUserToGroup (username, group) {
    try {
      await this.UserGroups.create({
        username: username,
        groupname: group
      });
    } catch (e) {
      return false;
    }
    return true;
  }

  async removeUserFromGroup (username, group) {
    await this.UserGroups.destroy({
      where: {
        username: username,
        groupname: group
      }
    });
  }
}

module.exports = SQLAuthDB;
