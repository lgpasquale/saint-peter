# saint-peter
This package provides a set of [express](https://expressjs.com) routers that handle authentication and user management.

## Binary
If you simply need to run an HTTP authentication server that provides user
management, you can use the command `saint-peter`:
```sh
node ./node_modules/.bin/saint-peter -p <port> -i <ip> --db sqlite://auth.sqlite
```
or add to the `scripts` section of your `package.json` something like:
```json
{
  "scripts": {
    "start-auth-server": "saint-peter -p <port> -i <ip> --db sqlite://<sqlite file to be created>"
  }
}
```
You can use any db supported by [sequelize](http://docs.sequelizejs.com) (e.g. `mysql://user:password@host:port/db`)

The section `defaultRouters` below describes all the HTTP resources provided by
this server.

The binary accepts the following command line options:
```
Options:
  --address, -a         address the server will listen on   [default: "0.0.0.0"]
  --port, -p            port the server will listen on           [default: 3000]
  --db                  database URL           [default: "sqlite://auth.sqlite"]
  --secret              secret used to generate the JSON Web Token
  --issuer, --iss       token issuer (iss field of the jwt)        [default: ""]
  --root-path, -r       root path; the API will be available as subpaths of this
                                                                  [default: "/"]
  --token-lifetime      token lifetime in seconds                [default: 3600]
  --token-idle-timeout  how long (in seconds) after a token has expired can it
                        be renewed without having to authenticate again
                                                                [default: 86400]
  --default-username    user created if no user is found      [default: "admin"]
  --default-password    password assigned to the default user [default: "admin"]
  --default-group       group created if no group is found    [default: "admin"]
```

## Library

In order to use this package as a library, instead, you need to require
`saint-peter`, which exports a class, and instantiate a an object of that type:
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
### Methods

#### `constructor (config, logger)`
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
  - userListVisibility: one of `public`, `authenticated`, `admin`; who can access (GET) the user list
  - groupListVisibility: one of `public`, `authenticated`, `admin`; who can access (GET) the group list
  - issuer: `iss` field to be written in the tokens
- **logger**: a logger that should provide at least two methods: `error` and `info`

#### `initializeDB ()`
Initialize the DB.
Returns a promise.
This method needs to be called in order for authentication (or anything else
that requires the db) to work. If saint-peter was not provided a `dbType`, you
don't need to call this method.

#### `static allowUsers (users, jwtSecret)`
Returns an express middleware that allows access only to given users
- **users**: array of user names
- **jwtSecret**: secret used to decode the JSON Web Token

#### `static allowGroups (groups, jwtSecret)`
Returns an express middleware that allows access only to users belonging to given groups
- **groups**: array of group names
- **jwtSecret**: secret used to decode the JSON Web Token

#### `static requireAuthentication (jwtSecret)`
Returns an express middleware that allows access only to authenticated users
- **jwtSecret**: secret used to decode the JSON Web Token

#### `defaultRouters (adminGroups = ['admin'])`
Returns a router that handles the following requests at these relative paths:
- `/authenticate` POST (`Content-type: applicatin/json`)

  Request body:
  ```json
  {
    "username": "<username>",
    "password": "<password>"
  }
  ```
  Response body:
  ```json
  {
    "success": true,
    "token": "token",
    "username": "username",
    "groups": "<user groups>",
    "email": "<user email>",
    "firstName": "<first name>",
    "lastName": "<last name>",
    "id": "<id>",
    "tokenExpirationDate": "<token expiration date (UNIX time)>"
  }
  ```
- `/renew-token`,  GET

  Request headers:
  ```
  Authorization: bearer <token>
  ```
  Response body:
  ```json
  {
    "success": true,
    "token": "token",
    "username": "username",
    "groups": "<user groups>",
    "email": "<user email>",
    "firstName": "<first name>",
    "lastName": "<last name>",
    "id": "<id>",
    "tokenExpirationDate": "<token expiration date (UNIX time)>"
  }
  ```

- `/users` POST (`Content-type: applicatin/json`)

  Only users belonging to an admin group can POST

  Request body:
  ```json
  {
    "username": "<username>",
    "password": "<password>"
  }
  ```
  Response body:
  ```json
  {
    "success": <true | flase>,
  }
  ```

- `/users` GET

  Only users belonging to an admin group can GET

  Response body (array of users):
  ```json
  [
    {
      "id": "<id>",
      "username": "<username>",
      "email": "<email>",
      "firstName": "<first name>",
      "lastName": "<last name>"
    },
    {...},
    ...
  ]
  ```

- `/users/<username>` GET

  Only users belonging to an admin group can GET

  Response body:
  ```json
  {
    "id": "<id>",
    "username": "<username>",
    "email": "<email>",
    "firstName": "<first name>",
    "lastName": "<last name>"
  }
  ```
  - `/users/<username>` DELETE

  Only users belonging to an admin group can DELETE

- `/users/<username>` PATCH (`Content-type: applicatin/json`)

  Only users belonging to an admin group can PATCH

  Request body:
  ```json
  {
    "id": "<id>",
    "username": "<username>",
    "email": "<email>",
    "firstName": "<first name>",
    "lastName": "<last name>"
  }
  ```

- `/users/<username>/groups` POST (`Content-type: applicatin/json`)

  Only users belonging to an admin group can POST

  Request body:
  ```json
  {
    "group": "<group>"
  }
  ```

- `/users/<username>/groups` DELETE

  Only users belonging to an admin group can DELETE

- `/users/<username>/email` PUT (`Content-type: applicatin/json`)

  Each user can update only its own email. Admins have no special power, they
  should instead use the PATCH `/users/<username>` resource.

  Request body:
  ```json
  {
    "email": "<email>"
  }
  ```

- `/users/<username>/password` PUT (`Content-type: applicatin/json`)

  Each user can update only its own password. Admins have no special power, they
  should instead use the PUT `/users/<username>/reset-password` resource.

  Request body:
  ```json
  {
    "oldPassword": "<old password>",
    "newPassword": "<new password>"
  }
  ```

- `/users/<username>/reset-password` PUT (`Content-type: applicatin/json`)

  Each user can update only its own password. Admins have no special power, they
  should instead use the PUT `/users/<username>/reset-password` resource.

  Request body:
  ```json
  {
    "password": "<password>",
  }
  ```

- `/groups` GET

  Only users belonging to an admin group can GET

  Response body (array of group names):
  ```json
  [
    "admin", "<group1>", "<group2>", ...
  ]
  ```

- `/groups` POST

  Only users belonging to an admin group can POST

  Request body:
  ```json
  {
    "group": "<group>"
  }
  ```

- `/groups/<group>` DELETE

  Only users belonging to an admin group can DELETE
