var forward = require('../forward.js');
var makeAuth = require('../auth.js');

var CONFIGS_TO_LOAD = {
  'config_disable_offline_sync': 'disableOfflineSync',
  'config_use_google_auth': 'useGoogleAuth',
  'config_log_metrics': 'logNetworkMetrics',
  'config_external_search': 'searchURL',
  'config_push_public_key': 'pushPublicKey'
};

module.exports = function(app, config) {
  var nano = require('nano')(config.couchAuthDbURL);
  var configDB = nano.use('config');
  var auth = makeAuth(config);

  function loadConfigs() {
    var configIds = Object.keys(CONFIGS_TO_LOAD);
    configDB.fetch({keys: configIds}, (err, configValues) => {
      if (err) {
        console.log('Error getting configurations to update', err);
      } else {
        let configsToUpdate = [];
        configValues.rows.forEach((configValue) => {
          var matchingConfig = CONFIGS_TO_LOAD[configValue.key];
          var valueFromConfigFile = config[matchingConfig];
           if (!valueFromConfigFile) {
             valueFromConfigFile = false;
           }
          if (configValue.key === 'config_external_search' &&
              valueFromConfigFile && valueFromConfigFile !== '') {
            valueFromConfigFile = true;
          }
          var dbConfigValue = '';
          if (!configValue.error && configValue.doc) {
            dbConfigValue = configValue.doc.value;
          }
          if (dbConfigValue !== valueFromConfigFile) {
            let docToUpdate = configValue.doc;
            if (!docToUpdate) {
              docToUpdate = {
                _id: configValue.key
              };
            }
            docToUpdate.value = valueFromConfigFile;
            configsToUpdate.push(docToUpdate);
          }
        });
        if (configsToUpdate.length > 0) {
          configDB.bulk({docs: configsToUpdate}, (err) => {
            if (err) {
              console.log('Error updating configs:', err);
            }
          });
        }
      }
    });

  }
  loadConfigs();

  if (config.isMultitenancy) {

    app.get(['/db/_users', '/db/_users/*'], function (req, res) {
      // proxy calls to db/_users
      var subdomain = req.subdomains.join('.');

      auth.getAuthenticatedUser(req, function (response) {
        if (response && response.role && (response.role === 'System Administrator' ||
          response.role === 'User Administrator')) {

          // download all users from the db and filter out users not authorized to this 
          // database and only show their role for this db.
          auth.findUsersForDB(subdomain, function (err, body) {
            res.json(err || body);
          });
        }
      });

    });
  }

  var forwarded = forward(config.couchDbURL, config, true);
  app.use('/db/', function (req, res) {
    if (config.isMultitenancy) {
      if (req.url.startsWith('/main/')) {
        var subdomain = req.subdomains.join('.');
        req.url = '/' + subdomain + req.url.substring(5);
      } else if (req.url === '/main') {
        var subdomain = req.subdomains.join('.');
        req.url = '/' + subdomain;
      }
    }

    return forwarded(req, res);
  });
};
