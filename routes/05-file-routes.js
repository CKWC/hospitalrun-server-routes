var express = require('express');
var url = require('url');
var AWS = require('aws-sdk');

function isS3URL(filePath) {
  return filePath.startsWith('s3://');
}

function parseS3URL(s3url) {

  if (s3url.startsWith('s3://')) {

    var q = url.parse(s3url, false, true);

    var paths = q.path.split('/');
    var bucket = paths[1];
    paths.splice(0, 2);
    var s3path = paths.join('/');

    return {
      endpoint: q.hostname,
      bucket: bucket,
      path: s3path
    };
  }

  return null;
}

function signedURLForS3URL(config, s3url) {
  var q = parseS3URL(s3url);

  var ep = new AWS.Endpoint(q.endpoint);
  var s3 = new AWS.S3({
    accessKeyId: config.awsAccessKeyId,
    secretAccessKey: config.awsSecretAccessKey,
    endpoint: ep
  });

  var params = {
    Key: q.path,
    Bucket: q.bucket
  };
  return s3.getSignedUrl('getObject', params);
}

module.exports = function (app, config) {

  if (isS3URL(config.imagesdir)) {

    app.get('/patientimages/*', function (req, res) {

      var requrl = config.imagesdir + req.url.substring(14);
      var s3url = signedURLForS3URL(config, requrl);
      res.redirect(s3url);
    });

  } else {
    app.use('/patientimages', express.static(config.imagesdir));
  }

  if (isS3URL(config.attachmentsDir)) {

    app.get('/attachments/*', function (req, res) {

      var requrl = config.attachmentsDir + req.url.substring(12);
      var s3url = signedURLForS3URL(onfig, requrl);
      res.redirect(s3url);
    });

  } else {
    app.use('/attachments', express.static(config.attachmentsDir));
  }
};
