var path = require('path');
var qs = require('querystring');

var async = require('async');
var bcrypt = require('bcryptjs');
var bodyParser = require('body-parser');
var colors = require('colors');
var cors = require('cors');
var express = require('express');
var logger = require('morgan');
var jwt = require('jwt-simple');
var moment = require('moment');
var mongoose = require('mongoose');
var request = require('request');
var https = require('https');

var config = require('./config');
var skills = require('./keywords');

var keywordSchema = new mongoose.Schema({
    name: String
});

var userSchema = new mongoose.Schema({
    email: { type: String, unique: true, lowercase: true },
    displayName: String,
    github: String,
    accessToken: String,
    login: String, 
    keywords : [{ type: mongoose.Schema.ObjectId, ref: 'Keyword' }]
});

var User = mongoose.model('User', userSchema);
var Keyword = mongoose.model('Keyword', keywordSchema);

mongoose.connect(config.MONGO_URI);
mongoose.connection.on('error', function(err) {
  console.log('Error: Could not connect to MongoDB. Did you forget to run `mongod`?'.red);
});

var app = express();

app.set('port', process.env.PORT || 3000);
app.use(cors());
app.use(logger('dev'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Force HTTPS on Heroku
if (app.get('env') === 'production') {
  app.use(function(req, res, next) {
    var protocol = req.get('x-forwarded-proto');
    protocol == 'https' ? next() : res.redirect('https://' + req.hostname + req.url);
  });
}

var staticPath = path.join(__dirname, '../src');

app.use(express.static(staticPath));

/*
 |--------------------------------------------------------------------------
 | Login Required Middleware
 |--------------------------------------------------------------------------
 */
function ensureAuthenticated(req, res, next) {
  if (!req.headers.authorization) {
    return res.status(401).send({ message: 'Please make sure your request has an Authorization header' });
  }
  var token = req.headers.authorization.split(' ')[1];

  var payload = null;
  try {
    payload = jwt.decode(token, config.TOKEN_SECRET);
  }
  catch (err) {
    return res.status(401).send({ message: err.message });
  }

  if (payload.exp <= moment().unix()) {
    return res.status(401).send({ message: 'Token has expired' });
  }
  req.user = payload.sub;
  next();
}

/*
 |--------------------------------------------------------------------------
 | Generate JSON Web Token
 |--------------------------------------------------------------------------
 */
function createJWT(user) {
  var payload = {
    sub: user._id,
    iat: moment().unix(),
    exp: moment().add(14, 'days').unix()
  };
  return jwt.encode(payload, config.TOKEN_SECRET);
}

/*
 |--------------------------------------------------------------------------
 | GET /api/me
 |--------------------------------------------------------------------------
 */
app.get('/api/me', ensureAuthenticated, function(req, res) {
    User.findById(req.user, function(err, user) {
        
        var toReturn = {};
        
        toReturn.id = user.id;
        toReturn.displayName = user.displayName;
        toReturn.github = user.github;
        toReturn.login = user.login;
        
        res.send(toReturn);
    });
});

/*
 |--------------------------------------------------------------------------
 | PUT /api/me
 |--------------------------------------------------------------------------
 */
app.put('/api/me', ensureAuthenticated, function(req, res) {
  User.findById(req.user, function(err, user) {
    if (!user) {
      return res.status(400).send({ message: 'User not found' });
    }
    user.displayName = req.body.displayName || user.displayName;
    user.email = req.body.email || user.email;
    user.save(function(err) {
      res.status(200).end();
    });
  });
});

/*
 |--------------------------------------------------------------------------
 | Login with GitHub
 |--------------------------------------------------------------------------
 */
app.post('/auth/github', function(req, res) {
  var accessTokenUrl = 'https://github.com/login/oauth/access_token';
  var userApiUrl = 'https://api.github.com/user';
  var params = {
    code: req.body.code,
    client_id: req.body.clientId,
    client_secret: config.GITHUB_SECRET,
    redirect_uri: req.body.redirectUri
  };

  // Step 1. Exchange authorization code for access token.
  request.get({ url: accessTokenUrl, qs: params }, function(err, response, accessTokenInfo) {
    var accessTokenInfoObj = qs.parse(accessTokenInfo);

    var headers = { 'User-Agent': 'Github-explorer' };

    // Step 2. Retrieve profile information about the current user.
    request.get({ url: userApiUrl, qs: accessTokenInfoObj, headers: headers, json: true }, function(err, response, profile) {

      // Step 3a. Link user accounts.
      if (req.headers.authorization) {
        User.findOne({ github: profile.id }, function(err, existingUser) {
          if (existingUser) {
            return res.send({ token: createJWT(existingUser) });
          }
          var token = req.headers.authorization.split(' ')[1];
          var payload = jwt.decode(token, config.TOKEN_SECRET);
          User.findById(payload.sub, function(err, user) {
            if (!user) {
              return res.status(400).send({ message: 'User not found' });
            }
            user.github = profile.id;
            user.displayName = user.displayName || profile.name;
            user.accessToken = accessTokenInfoObj.access_token;
            user.login = profile.login;
            
            user.save(function() {
              var token = createJWT(user);
              res.send({ token: token });
            });
          });
        });
      } else {
        // Step 3b. Create a new user account or return an existing one.
        User.findOne({ github: profile.id }, function(err, existingUser) {
          if (existingUser) {
            var token = createJWT(existingUser);
            return res.send({ token: token });
          }
          var user = new User();
          user.github = profile.id;
          user.picture = profile.avatar_url;
          user.displayName = profile.name;
          user.login = profile.login;
          
          user.accessToken = accessTokenInfoObj.access_token;
          user.save(function() {
            var token = createJWT(user);
            res.send({ token: token });
          });
        });
      }
    });
  });
});


/*
 |--------------------------------------------------------------------------
 | Unlink Provider
 |--------------------------------------------------------------------------
 */
app.post('/auth/unlink', ensureAuthenticated, function(req, res) {
  var provider = req.body.provider;
  var providers = [ 'github'];

  if (providers.indexOf(provider) === -1) {
    return res.status(400).send({ message: 'Unknown OAuth Provider' });
  }

  User.findById(req.user, function(err, user) {
    if (!user) {
      return res.status(400).send({ message: 'User Not Found' });
    }
    user[provider] = undefined;
    user.save(function() {
      res.status(200).end();
    });
  });
});

app.get('/api/details', ensureAuthenticated, function(req,res){
    
    var body = "";
    
    User.findById(req.user, function(err, user) {

        var githubRes = https.get({
            host : "api.github.com",
            path: '/user?access_token=' + user.accessToken,
            headers: {'user-agent': 'github-explorer-server'},
        }, (response) => {
            
            response.on('data',(d)=>{
                body += d;
            });
            
            response.on('end', ()=>{
                res.send(JSON.parse(body));
            });
        });
        
        githubRes.on('error', (e) => {
            console.error(e);
        });
            
        githubRes.end();
    });
});

app.get('/api/repos',ensureAuthenticated, function(req, res){
    var body = "";
    var repos;
    
    User.findById(req.user).populate('keywords').exec(function(err, user) {

        var githubRes = https.get({
            host : "api.github.com",
            path: '/user/repos?access_token=' + user.accessToken + "&type=owner",
            headers: {'user-agent': 'github-explorer-server'},
        }, (response) => {
            
            response.on('data',(d)=>{
                body += d;
            });
            
            response.on('end', ()=>{
                repos = JSON.parse(body);
                
                if(!Array.isArray(repos))
                    res.status(500).send({ message: 'Error while requesting the list of repos, see logs for details' });
                                
                var simpleRepoList = repos.map((repo)=> { return {
                    name : repo.name,
                    description: repo.description
                }});

                //list of unique languages 
                var languages = repos.map((repo) => repo.language).filter((value,index,self)=>self.indexOf(value)===index);
                var languageIds = keywordsCache.filter((item)=>languages.indexOf(item.name) !== -1);
                
                if(languageIds.length > 0){
                    
                    for(var i=0;i<languageIds.length;i++){
                        
                        var test = true;
                        for(var j=0;j<user.keywords.length;j++){

                            if(languageIds[i]._id.equals(user.keywords[j]._id)){
                                test = false;
                                break;
                            }
                        }
                        
                        //new element
                        if(test)
                            user.keywords.push(languageIds[i]._id);    
                    }
                    
                    user.save();
                }

                res.send(simpleRepoList);
            });
        });
        
        githubRes.on('error', (e) => {
            console.error(e);
        });
            
        githubRes.end();
    });
});

app.get('/api/skills', ensureAuthenticated, function(req, res){
     User.findById(req.user).populate('keywords').exec(function(err, user) {
         res.send(user.keywords);
     });
});

/*
 |--------------------------------------------------------------------------
 | Start the Server
 |--------------------------------------------------------------------------
 */

var keywordsCache;

app.listen(app.get('port'), function() {
  console.log('Express server listening on port ' + app.get('port'));
  var staticPath = path.join(__dirname, '../src');
  console.log('Site hosted at : ' + staticPath);
  
  console.log('checking the keyword table');
  
  //test if the collection contains at least one element
    Keyword.find((err, keywords)=> {
      
      //no element
      if(keywords.length == 0) {
          //we convert every skill into a keyword
          for(var i=0;i<skills.items.length;i++){
              var keyword = new Keyword({name:skills.items[i]});
              keyword.save();
              keywords.push(keyword);
          }
      }
      
      //elements in db
      else {
          var simpleKeywordList = keywords.map((keyword)=>keyword.name);

          var newSkills = skills.items.filter((skill)=>simpleKeywordList.indexOf(skill) === -1);
          
          newSkills.forEach((item)=>{
              var keyword = new Keyword({name:item});
              keyword.save();
              keywords.push(keyword);
          });
      }
      
        console.log('Keyword table filled');
        keywordsCache = keywords;
      
    });    
});