var fs = require('fs');
var PasswordHandler = require('./PasswordHandler');

function writeJSONFile (filename, data) {
  return new Promise((resolve, reject) => {
    fs.writeFile(filename, JSON.stringify(data), 'utf8', function (err) {
      if (err) reject(err);
      else resolve(data);
    });
  });
}

class FileAuthDB {
  constructor (config) {
    this.filename = config.filename;
    try {
      this.fileContents = JSON.parse(fs.readFileSync(this.filename, 'utf8'));
    } catch (e) {
      // unable to read file, create an empty db
      this.fileContents = {};
    }
    // create the 'users' table if it doesn't exist
    if (!('users' in this.fileContents)) {
      this.fileContents.users = {};
    }
    // create the 'groups' table if it doesn't exist
    if (!('groups' in this.fileContents)) {
      this.fileContents.groups = {};
    }
  }

  async authenticateUser (username, password) {
    return username in this.fileContents.users &&
      await PasswordHandler.verifyPassword(password, this.fileContents.users[username].password);
  }

  async getUserGroups (username) {
    return this.fileContents.users[username].groups;
  }

  async getUserEmail (username) {
    return this.fileContents.users[username].email;
  }

  async setUserEmail (username, email) {
    this.fileContents.users[username].email = email;
    await writeJSONFile(this.filename, this.fileContents);
  }

  async setUserPassword (username, password) {
    let combinedHash = await PasswordHandler.hashPassword(password);
    this.fileContents.users[username].password = combinedHash;
    await writeJSONFile(this.filename, this.fileContents);
  }

  async getUsers () {
    return Object.keys(this.fileContents.users);
  }

  async getGroups () {
    return Object.keys(this.fileContents.groups);
  }

  async addUser (username, password) {
    if (username in this.fileContents.users) {
      return false;
    }
    let combinedHash = await PasswordHandler.hashPassword(password);
    this.fileContents.users[username] = {
      username: username,
      password: combinedHash,
      groups: [],
      email: ''
    };
    await writeJSONFile(this.filename, this.fileContents);
    return true;
  }

  async deleteUser (username) {
    if (!(username in this.fileContents.users)) {
      return false;
    }
    delete this.fileContents.users[username];
    await writeJSONFile(this.filename, this.fileContents);
    return true;
  }

  async addGroup (group) {
    if (group in this.fileContents.groups) {
      return false;
    }
    this.fileContents.groups[group] = {};
    await writeJSONFile(this.filename, this.fileContents);
    return true;
  }

  async deleteGroup (group) {
    if (!(group in this.fileContents.group)) {
      return false;
    }
    delete this.fileContents.groups[group];
    await writeJSONFile(this.filename, this.fileContents);
    return true;
  }

  async addUserToGroup (username, group) {
    if (!(username in this.fileContents.users)) {
      throw new Error('User doesn\'t exist');
    }
    if (this.fileContents.users[username].groups.indexOf(group) < 0) {
      this.fileContents.users[username].groups.push(group);
    }
    await writeJSONFile(this.filename, this.fileContents);
    return true;
  }

  async removeUserFromGroup (username, group) {
    if (!(username in this.fileContents.users)) {
      throw new Error('User doesn\'t exist');
    }
    let index = this.fileContents.users[username].groups.indexOf(group);
    if (index >= 0) {
      this.fileContents.users[username].groups.splice(index, 1);
    }
    return await writeJSONFile(this.filename, this.fileContents);
  }
}

module.exports = FileAuthDB;
