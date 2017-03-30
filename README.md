# saint-peter
This package provides a set of [express](https://expressjs.com) routers that handle authentication and user management

In order to use this library you need to require `saint-peter`, which exports a
class, and instantiate a an object of that type:
```javascript
var express = require('express');
var SaintPeter = require('saint-peter');

var config = {
  jwtSecret: 'secret',
  dbType: 'sqlite',
  storage: './authdb.sqlite'
};
var saintPeter = new SaintPeter(config);

var app = express();
app.use('/', saintPeter.defaultRouters(['admin']));
saintPeter.initializeDB().then(() => {
  app.listen(3000, () => console.log('Auth server listening on port 3000'))
}).catch((e) => console.log(e.stack));
```
## Methods

### `constructor (config, logger)`
The constructor takes two arguments:
- **config**: object containing the following items:
  - jwtSecret: secret used for jwt encryption
  - dbType: string, one of `mysql`, `sqlite` (defaults to `sqlite`); if no
    dbType is given (or if dbType is set to `null`) saint-peter can only be used
    to authorize requests (by using the `allowUsers`, `allowgroups` and
    `requireAuthentication` methos)
  - storage: sqlite db file (only used if dbType is sqlite)
  - host: auth db hostname
  - port: auth db port
  - database: auth db name
  - username: auth db username
  - password: auth db password
  - defaultUsername: string, if no user is found in the database, one is created using this username (default to `admin`)
  - defaultGroup: string, if no user is found in the database, one is created belonging to this groups (default to `admin`)
  - defaultPassword: string, if no user is found in the database, one is created with this password (defaults to `admin`)
  - tokenLifetime: integer, number of seconds before a generated token expires
  - tokenIdleTimeout: integer, number of seconds a token can be renewed after it's's expired
- **logger**: a logger that should provide at least two methods: `error` and `info`

### `initializeDB ()`
Initialize the DB.
Returns a promise.
This method needs to be called in order for authentication (or anything else
that requires the db) to work. If saint-peter was not provided a `dbType`, you
don't need to call this method.

### `allowUsers (users)`
Returns a router that allows access only to given users
- **users**: array of user names

### `allowGroups (groups)`
Returns a router that allows access only to users belonging to given groups
- **groups**: array of group names

### `requireAuthentication ()`
Returns a router that allows access only to authenticated users

### `defaultRouters (adminGroups = ['admin'])`
Returns a router that handles the following requests at these relative paths:
- `/authenticate` -> `authenticate()`
- `/renew-token`, `renewToken()`
- `/add-user` -> `addUser()`.
Only users belonging to one of `adminGroups` are allowed
- `/delete-user` -> `deleteUser()`.
Only users belonging to one of `adminGroups` are allowed
- `/add-group` -> `addUser()`.
Only users belonging to one of `adminGroups` are allowed
- `/delete-group` -> `deleteUser()`.
Only users belonging to one of `adminGroups` are allowed
- `/add-user-to-group` -> `addUserToGroup()`.
Only users belonging to one of `adminGroups` are allowed
- `/remove-user-from-group` -> `this.removeUserFromGroup()`.
Only users belonging to one of `adminGroups` are allowed
- `/set-user-email` -> `setUserEmail()``
- `/set-user-password` -> `setUserPassword()`
- `/reset-user-password` -> `resetUserPassword()`.
Only users belonging to one of `adminGroups` are allowed
- `/set-user-info` -> `setUserInfo()`.
Only users belonging to one of `adminGroups` are allowed
- `/get-users-info` -> `getUsersInfo()`.
Only users belonging to one of `adminGroups` are allowed
- `/get-users` -> `getUsers()`.
Only users belonging to one of `adminGroups` are allowed
- `/get-groups` -> `.getGroups()`.
Only users belonging to one of `adminGroups` are allowed
