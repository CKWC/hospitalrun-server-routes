var serializer = require('serializer');
var request = require('request');

function createSecret(secretBase) {
  var encryptKey = serializer.randomString(48);
  var validateKey = serializer.randomString(48);
  var secretString = serializer.secureStringify(secretBase, encryptKey, validateKey);
  if (secretString.length > 80) {
    secretString = secretString.substr(30, 50);
  }
  return secretString;
}

function denormalizeOAuth(user) {
  var key;
  for (key in user.oauth.consumer_keys) {
    user.consumer_key = key;
    user.consumer_secret = user.oauth.consumer_keys[key];
    break;
  }
  for (key in user.oauth.tokens) {
    user.token_key = key;
    user.token_secret = user.oauth.tokens[key];
    break;
  }
  return user;
}

function validateOAuth(oauth) {
  try {
    if (Object.keys(oauth.consumer_keys).length > 0 && Object.keys(oauth.tokens).length > 0) {
      return true;
    }
  } catch (ex) {
    // Oauth is bad, just let the false return;
  }
  return false;
}

function getPrimaryRole(config, user, subdomain) {
  var primaryRole = '';

  if (user.roles) {
    user.roles.forEach(function (role) {

      var p = role.indexOf('.');
      if (config.isMultitenancy && p >= 0) {

        var db = role.substr(0, p);
        if (db !== subdomain) {
          return;
        }

        role = role.substr(p + 1);

      } else if (p >= 0) {
        return;
      }

      if (role !== 'user' && role !== 'admin') {
        primaryRole = role;
      }
    });
  }
  return primaryRole;
}

function getRoles(config, user, subdomain) {
  var roles =  [];
  if (user.roles) {
    user.roles.forEach(function (role) {

      var p = role.indexOf('.');
      if (config.isMultitenancy && p >= 0) {

        var db = role.substr(0, p);
        if (db !== subdomain) {
          return;
        }

        role = role.substr(p + 1);

      } else if (p >= 0) {
        return;
      }

      roles.push(role);
    });
  }

  return roles;
}

module.exports = function (config) {

  var nano = require('nano')(config.couchAuthDbURL);
  var users = nano.use('_users');

  function createOAuthTokens(secretBase, user, callback) {
    var consumerKey = serializer.randomString(96);
    var tokenKey = serializer.randomString(96);
    user.oauth = {
      consumer_keys: {},
      tokens: {},
    };
    user.oauth.consumer_keys[consumerKey] = createSecret(secretBase);
    user.oauth.tokens[tokenKey] = createSecret(secretBase);
    users.insert(user, user._id, function (err, response) {
      if (err || !response.ok) {
        callback(response);
      } else {
        callback(null, denormalizeOAuth(user));
      }
    });
  }

  function findOAuthUser(request, accessToken, refreshToken, profile, callback) {
    var hostname = request.query.state;
    var userKey = 'org.couchdb.user:' + profile.emails[0].value;
    users.get(userKey, {}, function (err, body) {
      if (err) {
        if (err.error && err.error === 'not_found') {
          callback(null, false);
        } else {
          callback(err);
        }
        return;
      }
      if (body.deleted) {
        callback(null, false);
        return;
      }
      if (validateOAuth(body.oauth)) {
        callback(null, denormalizeOAuth(body));
      } else {
        createOAuthTokens(accessToken, body, callback);
      }
    });
  }

  function findUser(userName, callback) {
    var userKey = userName;
    if (userKey.indexOf('org.couchdb.user:') !== 0) {
      userKey = 'org.couchdb.user:' + userKey;
    }
    users.get(userKey, {}, function (err, body) {
      if (err) {
        callback(err);
        return;
      }
      if (body && body.deleted) {
        callback(true);
        return;
      }
      if (validateOAuth(body.oauth)) {
        callback(null, denormalizeOAuth(body));
      } else {
        createOAuthTokens(serializer.randomString(48), body, callback);
      }
    });
  }

  function getAuthenticatedUser(req, cb) {

    if (!req.get('x-oauth-consumer-key')) {
      return cb({ error: true, errorResult: 'You are not authorized' });
    }

    var requestOptions = {
      oauth: {
        consumer_key: req.get('x-oauth-consumer-key'),
        consumer_secret: req.get('x-oauth-consumer-secret'),
        token: req.get('x-oauth-token'),
        token_secret: req.get('x-oauth-token-secret')
      }
    };

    return getSession(req, requestOptions, false, null, cb);
  }

  function getSession(req, requestOptions, includeOauth, username, cb) {
    var subdomain = req.subdomains.join('.');

    requestOptions.url = config.couchDbURL + '/_session';
    request(requestOptions, function (error, response, body) {

      if (error) {
        cb({ error: true, errorResult: error });
      } else {
        var userSession = JSON.parse(body);
        var userDetails = userSession.userCtx || userSession;

        if (!username || userDetails.name === username) {
          // User names match; we should respond with requested info
          findUser(userDetails.name, function (err, user) {
            if (err) {
              cb({ error: true, errorResult: err });
            } else {
              var response = {
                name: userDetails.name,
                displayName: user.displayName,
                prefix: user.userPrefix,
                role: getPrimaryRole(config, user, subdomain)
              };
              if (includeOauth) {
                response.k = user.consumer_key;
                response.s1 = user.consumer_secret;
                response.t = user.token_key;
                response.s2 = user.token_secret;
              }
              cb(response);
            }
          });
        } else {
          // User names don't match, throw error!
          cb({ error: true, errorResult: 'You are not authorized' });
        }
      }
    });
  }

  function findUsersForDB(subdomain, cb) {

    return users.list({
      include_docs: true,
      startkey: 'org.couchdb.user'
    }, function (err, response) {

      if (err || !response) {
        cb(err);
      } else {

        var rows = [];

        response.rows.forEach(row => {
          var roles = getRoles(config, row.doc, subdomain);
          if (roles && roles.length > 0) {

            const { _id, _rev, derived_key, deleted, displayName, email, iterations, name, password,
              password_scheme, password_sha, type, salt, userPrefix  } = row.doc;
            row.doc = {
              _id,
              _rev,
              id: _id,
              rev: _rev,
              derived_key, deleted, displayName, email, iterations, name, password,
              password_scheme, password_sha, type, salt, userPrefix,
              roles: roles
            };

            rows.push(row);
          }
        });

        cb(null, {
          total_rows: rows.length,
          offset: 0,
          rows: rows
        });
      }
    });
  }

  return {
    findUser: findUser,
    findOAuthUser: findOAuthUser,
    getAuthenticatedUser: getAuthenticatedUser,
    getSession: getSession,
    findUsersForDB: findUsersForDB,
    getPrimaryRole: function (user, subdomain) {
      return getPrimaryRole(config, user, subdomain);
    },
    getRoles: function (user, subdomain) {
      return getRoles(config, user, subdomain);
    }
  };
};
