# saint-peter
This package provides a set of express routers that handle authentication and user management

In order to use this library you need to require `saint-peter`, which exports a
class and instantiate a an object of that type:
```javascript
var SaintPeter = requrie('saint-peter')
var saintPeter = new SaintPeter(config)
saintPeter.initializeDB() // returns a promise
```

The constructor takes two arguments:
- config: object containing the following items:
  - dbType: string, one of `mysql`, `sqlite` (defaults to `sqlite`)
  - storage: sqlite db file (only used if dbType is sqlite)
  - host: auth db hostname
  - port: auth db port
  - database: auth db name
  - username: auth db username
  - password: auth db password
  - jwtSecret: secret used for jwt encryption
  - defaultUsername: string, if no user is found in the database, one is created using this username (default to `admin`)
  - defaultGroup: string, if no user is found in the database, one is created belonging to this groups (default to `admin`)
  - defaultPassword: string, if no user is found in the database, one is created with this password (defaults to `admin`)
  - tokenLifetime: integer, number of seconds before a generated token expires
  - tokenIdleTimeout: integer, number of seconds a token can be renewed after it's's expired
- logger: a logger that should provide at least two methods: `error` and `info`
