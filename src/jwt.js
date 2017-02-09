var jwt = require('jsonwebtoken');

/**
 * This is a wrapper for jwt.verify(...) that returns a promise
 * and takes its same arguments (except for the callback)
 * @param token the request
 * @param jwtSecret secret to be used for decoding the token
 * @param options to be passed to jwt.verify(...)
 */
function decodeToken (token, jwtSecret, options) {
  return new Promise((resolve, reject) => {
    jwt.verify(token, jwtSecret, options, (err, decodedToken) => {
      if (err) {
        return reject(err);
      }
      return resolve(decodedToken);
    });
  });
}

/**
 * Given a request and a secret try to decode the token.
 * This function takes the same arguments as jwt.verify(...),
 * except for the first argument (reqest instead of the token)
 * @param req the request
 * @param jwtSecret secret to be used for decoding the token
 * @param options to be passed to jwt.verify(...)
 */
function decodeTokenHeader (req, jwtSecret, options) {
  return new Promise((resolve, reject) => {
    let authHeader = req.get('Authorization');
    if (authHeader) {
      var parts = authHeader.split(' ');
      if (parts.length >= 2 &&
          parts[0].toLowerCase() === 'bearer') {
        let token = parts[1];
        jwt.verify(token, jwtSecret, options, (err, decodedToken) => {
          if (err) {
            return reject(err);
          }
          return resolve(decodedToken);
        });
        return;
      }
      // if we made it here we failed parsing the error
      throw new Error('Error parsing Authorization header');
    }
    throw new Error('No Authorization header');
  });
}

/**
 * Given a token and a secret try to encode the token.
 * This function takes the same arguments as jwt.verify(...),
 * @param token the token to encode
 * @param jwtSecret secret to be used for encoding the token
 * @param options to be passed to jwt.verify(...)
 */
function encodeToken (token, jwtSecret, options) {
  return new Promise((resolve, reject) => {
    jwt.sign(token, jwtSecret, options, (err, encodedToken) => {
      if (err) return reject(err);
      resolve(encodedToken);
    });
  });
}

exports.decodeToken = decodeToken;
exports.decodeTokenHeader = decodeTokenHeader;
exports.encodeToken = encodeToken;
