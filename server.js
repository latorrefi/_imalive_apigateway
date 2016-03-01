var http = require('http');
var https = require('https');
var url = require('url');
/*var jwt = require('jsonwebtoken');*/
var jwt = require('jwt-simple');
var mongoose = require('mongoose');
var morgan = require('morgan');
var sprintf = require('sprintf');
var Q = require('q');
var _ = require('underscore');
var amqp = require('amqp');
var crypto = require('crypto');
var moment = require('moment');
var config = require('./config');

var logger = require('./logger');

var util = require('./util');

var amqpHost = process.env.AMQP_HOST || 'amqp://wcvabgeb:rfTHtEtqA1GtFe6M_32oIJ6OG-YflqWm@chicken.rmq.cloudamqp.com/wcvabgeb';

var httpLogger = morgan('combined', { stream: logger.stream });

var realm = "imalive_reg",
  opaque=  md5(realm);

function toBase64(obj) {
    return new Buffer(JSON.stringify(obj)).toString('base64');
}

var amqpConn = amqp.createConnection({url: amqpHost});

// q
mongoose.Promise = Q.Promise;


mongoose.connection.close();
mongoose.connect(config.database);


var Users = require("./model/users").Users;
var UserNumbers = require("./model/usernumbers").UserNumbers;
var Service = require("./model/service").Service;



var secretKey = config.secret;
var issuerStr = "Sample API Gateway"


function send500(res) {
    res.statusCode = 500;
    res.end();
}

function send400(res) {
    res.statusCode = 400;
    res.end();
}

function send404(res) {
    res.statusCode = 404;
    res.end();
}

function send201(req,res,id,json) {
    res.statusCode = 201;
    res.setHeader("Access-Control-Allow-Origin", "https://imalive-reg-fe-ghiron.c9users.io");
    res.setHeader("Location", req.headers['x-forwarded-proto'] + '://' + req.headers.host + req.originalUrl+'/'+id);
    res.setHeader("Content-Location", req.headers['x-forwarded-proto'] + '://' +req.headers.host + req.originalUrl+'/'+id);
    res.setHeader("Content-Type", "application/json;charset=UTF-8");
    res.end(JSON.stringify(json));
}

/* Get all pending data from HTTP request */
function getData(req) {
    var result = Q.defer();
    
    var data = "";
    req.on('data', function(data_) {
        data += data_;
        if(data.length >= (1024 * 1024)) {
            data = "";
            result.reject("Bad request");
        }
    });
    
    req.on('end', function() {
        if(result.promise.isPending()) {
            try {
                result.resolve(data);
            } catch(err) {
                result.reject(err.toString());
            }
        }
    });
    
    return result.promise;
}


function doRegistration(req, res) {
    getData(req).then(function(data) { 
        try {
            var registrationData = JSON.parse(data);
            if(util.isValid(registrationData)){
              var query = UserNumbers.findOne({});
              // selecting the `name` and `occupation` fields
              query.select('usernumber');
              // execute the query at a later time
              var promiseCreateUserNumber = query.exec();
              var created_user_number;
              promiseCreateUserNumber.then(function(newnumber) {
                created_user_number = newnumber.usernumber;
                return newnumber.remove();
              })
              .then(function(){
                var hash = md5(created_user_number + ':' + realm + ':' + registrationData.password);
                var newActiveUser =  new Users({usernumber:created_user_number , password: hash ,mail:registrationData.email  });
                return newActiveUser.save();
              })
              .then(function(newActiveUser){
                 send201(req,res,newActiveUser.usernumber,newActiveUser);
              })
              .catch(function(err){
                logger.error(err);            
                send500(res);
              });
            }else{
                logger.error('Validation failed');            
                send400(res);
            }
        } catch(err) {
            logger.error(err);            
            send500(res);
        }
    }, function(err) {
        logger.error(err);            
        send500(res);
    });
}


function md5(msg) {
  return crypto.createHash('md5').update(msg).digest('hex');
}



function send401(res) {
  res.writeHead(401, {
    'WWW-Authenticate' : 'Digest realm="' + realm + '"'
    + ',qop="auth",nonce="' + Math.random() + '"'
    + ',opaque="' + opaque + '"'});

  res.end('Authorization required.');
}

function parseAuth(auth) {
  var authObj = {};
  auth.split(', ').forEach(function (pair) {
    pair = pair.split('=');
    authObj[pair[0]] = pair[1].replace(/"/g, '');
  });
  return authObj;
}

/*
 * Digest login: returns a JWT if login data is valid.
 */
function doLogin(req, res) {
    getData(req).then(function(data) { 
        try {
            var auth, digest = {};
            if (!req.headers.authorization) {
              send401(res);
              return;
            }
            auth = req.headers.authorization.replace(/^Digest /, '');
            auth = parseAuth(auth);
            //var password = req.body.password;
            var usernumber = auth.username;
            var query = Users.findOne({ usernumber: usernumber});
            // execute the query at a later time
            var promiseCreateUserNumber = query.exec();
            promiseCreateUserNumber.then(function(user) {
              if(user!==undefined){
                digest.ha1 = user.password;
                digest.ha2 = md5(req.method + ':' + auth.uri);
                digest.response = md5([
                  digest.ha1,
                  auth.nonce, auth.nc, auth.cnonce, auth.qop,
                  digest.ha2
                ].join(':'));
                
                if (auth.response !== digest.response) { send401(res); return; }
                var expires = moment().add(7,'days').valueOf();
                var token = jwt.encode({
                  iss: user.usernumber,
                  exp: expires
                }, secretKey);
                res.writeHeader(200, {
                  'Content-Length': token.length,
                  'Content-Type': "text/plain"
                });
                res.write(token);
                res.end();    
              }else{
                send401(res); return;
              }
            })
            .catch(function(err){
                logger.error(err);            
                send500(res);
            });
        } catch(err) {
            logger.error(err);            
            send401(res);
        }
    }, function(err) {
        logger.error(err);            
        send401(res);
    });
}

/*
 * Authentication validation using JWT. Strategy: find existing user.
 */
function validateAuth(data, callback) {
    if(!data) {
        callback(null);
        return;
    }
    
    data = data.split(" ");
    if(data[0] !== "Bearer" || !data[1]) {
        callback(null);
        return;
    }
    var token = data[1];
    //var token = (req.body && req.body.access_token) || (req.query && req.query.access_token) || req.headers['x-access-token'];
    if (token) {
      try {
        var payload = jwt.decode(token, secretKey);
        // handle token here
        if (payload.exp <= Date.now()) {
          logger.error('Access token has expired');
          callback(null);
          /*res.end('Access token has expired', 400);*/
        }
        var promise = Users.findOne({ usernumber: payload.iss}).exec();
        promise.then(function(user) {
          if(user===null){
            /*send404(res);*/
            logger.error('No user exist');
            callback(null);
          }else{
            callback({
                    user: user,
                    jwt: payload 
                });
          }
        })
        .catch(function(err){
          logger.error(err);
          callback(null);
        });
        
      } catch(err) {
        logger.error(err);
        callback(null);
      }
    }else{
      logger.error('Token not exists');
      callback(null);
    }
}

/*
 * Internal HTTP request, auth data is passed in headers.
 */
function httpSend(oldReq, endpoint, data, deferred, isGet) {
    var parsedEndpoint = url.parse(endpoint);

    var options = {
        hostname: parsedEndpoint.hostname,
        port: parsedEndpoint.port,
        path: parsedEndpoint.path,
        method: isGet ? 'GET' : 'POST',
        headers: isGet ? {} : {
            'Content-Type': 'application/json',
            'Content-Length': data.length,
            'GatewayAuth': toBase64(oldReq.authPayload)
        }
    };

    var prot = options.port == 443 ? https : http;
    var req = prot.request(options, function(res) {
        var resData = "";
        res.on('data', function (chunk) {
            resData += chunk;
        });
        res.on('end', function() {
            try {
                var json = JSON.parse(resData);
                deferred.resolve(json);
            } catch(err) {
                deferred.reject({
                    req: oldReq, 
                    endpoint: endpoint, 
                    message: 'Invalid data format: ' + err.toString()
                });
            }
        });
    });

    req.on('error', function(e) {
        deferred.reject({
            req: oldReq, 
            endpoint: endpoint, 
            message: e.toString()
        });
    });

    if(!isGet && data) {
        req.write(data);
    }
    req.end();
}

function urlBuilder(parsedUrl,pathBuilder){
    var secondUrlPart;
    var queryRegex = /\{[q]([^}]+)\}/;
    var queryMatches = queryRegex.exec(pathBuilder);
    if(queryMatches){
        var index = queryMatches[1];
        var queries = parsedUrl.query.split("&");
        pathBuilder = pathBuilder.replace(queryRegex,queries[index]);
    }
    var pathnameRegex =  /\{[p]([^}]+)\}/;
    var pathnameMatches = pathnameRegex.exec(pathBuilder);
    if(pathnameMatches){
        var index = pathnameMatches[1];
        var queries = parsedUrl.pathname.split("/");
        pathBuilder = pathBuilder.replace(pathnameRegex,queries[index]);
    }
    secondUrlPart = pathBuilder;
    return secondUrlPart;
}
/* 
 * Internal HTTP request
 */
function httpPromise(req, endpoint, isGet) {
    var result = Q.defer();
    
    function reject(msg) {
        result.reject({
            req: req, 
            endpoint: endpoint, 
            message: msg
        });
    }
    
    if(isGet) {
        httpSend(req, endpoint, null, result, isGet);
    } else {
        getData(req).then(function(data) {
            httpSend(req, endpoint, data, result, isGet);
        }, function(err) {
            reject(err);
        });
    }
    
    return result.promise;
}

function amqpSend(req, endpoint, data, result) {
    amqpConn.queue('', {
        exclusive: true
    }, function(queue) {
        queue.bind('#');
        
        queue.subscribe({ ack: true, prefetchCount: 1 }, 
            function(message, headers, deliveryInfo, messageObject) {
                messageObject.acknowledge();
                
                try {
                    var json = JSON.parse(message);
                    deferred.resolve(json);
                } catch(err) {
                    deferred.reject({
                        req: req, 
                        endpoint: endpoint, 
                        message: 'Invalid data format: ' + err.toString()
                    });
                }               
            }
        );
        
        //Default exchange
        var exchange = amqpConn.exchange();
        //Send data
        exchange.publish(endpoint, data ? data : {}, {
            headers: {
                'GatewayAuth': toBase64(req.authPayload),                
            },
            deliveryMode: 1, //non-persistent
            replyTo: queue.name,
            mandatory: true,
            immediate: true
        }, function(err) {
            if(err) {
                deferred.reject({
                    req: req, 
                    endpoint: endpoint, 
                    message: 'Could not publish message to the default ' + 
                             'AMQP exchange'
                });
            }
        });
    });
}

/* 
 * Internal AMQP request
 */
function amqpPromise(req, endpoint, isGet) {
    var result = Q.defer();
    
    function reject(msg) {
        result.reject({
            req: req, 
            endpoint: endpoint, 
            message: msg
        });
    }
    
    if(req.method === 'POST') {
        getData(req).then(function(data) {
            amqpSend(req, endpoint, data, result);
        }, function(err) {
            reject(err);
        });        
    } else {
        amqpSend(req, endpoint, null, result);
    }
    
    return result.promise;
}

function roleCheck(user, service) {
    var intersection = _.intersection(user.roles, service.authorizedRoles);
    return intersection.length === service.authorizedRoles.length;
}

/* 
 * Parses the request and dispatches multiple concurrent requests to each
 * internal endpoint. Results are aggregated and returned.
 */
function serviceDispatch(req, res) {
    var parsedUrl = url.parse(req.url);
    var pathnames = parsedUrl.pathname.split("/");
    Service.findOne({ url: pathnames[1] }, function(err, service) {
        if(err) {
            logger.error(err);
            send500(res);
            return;
        }
    
        var authorized = roleCheck(req.context.authPayload.user, service);
        if(!authorized) {
            send401(res);
            return;
        }       
        
        // Fanout all requests to all related endpoints. 
        // Results are aggregated (more complex strategies are possible).
        var promises = [];
       
        service.endpoints.forEach(function(endpoint) {   
            var urlSecondPart = urlBuilder(parsedUrl,endpoint.path_builder);
            endpoint.url = endpoint.url+urlSecondPart;
            logger.debug(sprintf('Dispatching request from public endpoint ' + 
                '%s to internal endpoint %s (%s)', 
                req.url, endpoint.url, endpoint.type));
            //TODO Make a data builder
            //Data builder have to examine parsedUrl and make the new endopoint url
            /*example : Item that data builder can anylize: 
            pathname: The path section of the URL, that comes after the host and before the query, including the initial slash if present. No decoding is performed.
            Example: '/p/a/t/h'
            
            search: The 'query string' portion of the URL, including the leading question mark.Array.
            Example: '?query=string'
            
            path: Concatenation of pathname and search. No decoding is performed.Array.
            Example: '/p/a/t/h?query=string'
            
            query: Either the 'params' portion of the query string, or a querystring-parsed object.Array.
            Example: 'query=string' or {'query':'string'}*/
            
            
            switch(endpoint.type) {
                case 'http-get':
                case 'http-post':
                    promises.push(httpPromise(req, endpoint.url, 
                        endpoint.type === 'http-get'));
                    break;
                case 'amqp':
                    promises.push(amqpPromise(req, endpoint.url));
                    break;
                default:
                    logger.error('Unknown endpoint type: ' + endpoint.type);
            }            
        });
        
        //Aggregation strategy for multiple endpoints.
        Q.allSettled(promises).then(function(results) {
            var responseData = {};
        
            results.forEach(function(result) {
                if(result.state === 'fulfilled') {
                    responseData = _.extend(responseData, result.value);
                } else {
                    logger.error(result.reason.message);
                }
            });
            
            res.setHeader('Content-Type', 'application/json');
            res.end(JSON.stringify(responseData));
        });
    }, 'services');
}

var server = http.createServer(function(req, res) {
    httpLogger(req, res, function(){});

    // Login endpoint
    if(req.url === "/login" && req.method === 'POST') {
        doLogin(req, res);
        return;
    }

    //Registration endopoint
    if(req.url === "/users" && req.method === 'POST') {
        doRegistration(req, res);
        return;
    }
    
    // Authentication
    var authHeader = req.headers["authorization"];
    validateAuth(authHeader, function(authPayload) {
        if(!authPayload) {
            send401(res);
            return;
        }
        
        // We keep the authentication payload to pass it to 
        // microservices decoded.
        req.context = {
            authPayload: authPayload
        };
        
        serviceDispatch(req, res);        
    });
});

server.listen(process.env.PORT || 3000, process.env.IP || "0.0.0.0", function(){
  var addr = server.address();
  console.log("Server listening at", addr.address + ":" + addr.port);
});