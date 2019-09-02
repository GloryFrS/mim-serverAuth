const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const withAuth = require('./middleware');
// const _ = require('lodash');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcrypt');


// vk
const VKontakteStrategy = require('passport-vkontakte').Strategy;
// 

const https 	       = require('https');
const http 	         = require('http');

const fs             = require('fs');
const axios = require('axios');

const privateKey = fs.readFileSync("/etc/letsencrypt/live/vk.masterimodel.com/privkey.pem", 'utf8');
const certificate = fs.readFileSync("/etc/letsencrypt/live/vk.masterimodel.com/fullchain.pem", 'utf8');
const credentials = { key: privateKey, cert: certificate };


const passport = require('passport');
const passportJWT = require('passport-jwt');

let ExtractJwt = passportJWT.ExtractJwt;
let JwtStrategy = passportJWT.Strategy;

let jwtOptions = {};
jwtOptions.jwtFromRequest = ExtractJwt.fromAuthHeaderAsBearerToken();
jwtOptions.secretOrKey = 'wowwow';

// lets create our strategy for web token
let strategy = new JwtStrategy(jwtOptions, function(jwt_payload, next) {
  console.log('payload received', jwt_payload);
  let user = getUser({ id: jwt_payload.id });

  if (user) {
    next(null, user);
  } else {
    next(null, false);
  }
});
// use the strategy
passport.use(strategy);

const app = express();
app.use(require('express-session')({secret:'keyboard cat', resave: true, saveUninitialized: true}));

// initialize passport with express
app.use(passport.initialize());
app.use(passport.session());
app.use(cors())
// parse application/json
app.use(bodyParser.json());
//parse application/x-www-form-urlencoded
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());


app.use(function(req, res, next) {
  res.header("Access-Control-Allow-Credentials", true);
  res.header("Access-Control-Allow-Origin", req.headers.origin);
  res.header("Access-Control-Allow-Methods", "GET,PUT,POST,DELETE");
  res.header(
    "Access-Control-Allow-Headers",
    "X-Requested-With, X-HTTP-Method-Override, Content-Type, Accept"
  );
  if ("OPTIONS" == req.method) {
    res.send(200);
  } else {
    next();
  }
});



const Sequelize = require('sequelize');

// initialze an instance of Sequelize
const sequelize = new Sequelize({
  database: 'users',
  username: 'phpmyadmin',
  password: 'yAF9XMNYP9NyTc2C',
  dialect: 'mysql',
});

// check the databse connection
sequelize
  .authenticate()
  .then(() => console.log('Connection has been established successfully.'))
  .catch(err => console.error('Unable to connect to the database:', err));

// create user model
const User = sequelize.define('user', {
  name: {
    type: Sequelize.STRING
  },
  password: {
    type: Sequelize.STRING,
  },
});

// create table with user model
User.sync()
  .then(() => console.log('User table created successfully'))
  .catch(err => console.log('oooh, did you enter wrong database credentials?'));

// create some helper functions to work on the database
const createUser = async ({ name, password }) => {
  return await User.create({ name, password });
};

const getAllUsers = async () => {
  return await User.findAll();
};

const getUser = async obj => {
  return await User.findOne({
    where: obj,
  });
};
const updateUser = async (name ,newPassword) => {
  return await User.update({ password: newPassword }, { where: {name: name} });
}


passport.use(new VKontakteStrategy(
  {
    clientID:     '7044956', // VK.com docs call it 'API ID', 'app_id', 'api_id', 'client_id' or 'apiId'
    clientSecret: 'oi4hFl6BxhhmEiCJimuV',
    callbackURL:  "https://vk.masterimodel.com:3005/auth/vkontakte/callback"
  },
  function myVerifyCallbackFn(accessToken, refreshToken, params, profile, done) {
    
        done(null, profile);
        
  }
));
passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id)
      .then(function (user) { done(null, user); })
      .catch(done);
});

// get all users
app.get('/users', function(req, res) {
  getAllUsers().then(user => res.json(user));
});

// register route
app.post('/register', async function(req, res, next) {
  let { name, password } = req.body;
  name = parseInt(name, 10);
  const saltRounds = 10;

  if (isNaN(name)) {
    res.status(204).end();
  } else {
    let user = await getUser({ name: name });
    if(user){
      res.status(202).end();
    } else {
      if (name && password) {
          const passwordWrite = await bcrypt.hash(password, saltRounds);
          if(passwordWrite) {
            password = passwordWrite;
            createUser({ name, password }).then(user =>
              res.json({ user, msg: 'account created successfully' })
            );
          } else {
            res.json({msg: 'err validation' })
          }
      }
    }    
  }
  
  
});
app.post('/editPassword', async function(req, res, next) {
  let { name, password } = req.body;
  const saltRounds = 10;
  let user = await getUser({ name: name });
  if(!user){
    res.status(202).json({status: "Не найден"});
  } else {
    if (name && password) {
      const passwordWrite = await bcrypt.hash(password, saltRounds); //новый пароль
      if(passwordWrite) {
        password = passwordWrite;
        updateUser(name, password ).then(user =>
          res.json({ user, msg: 'password change successfully' })
        );
      }else {
        res.json({msg: 'err validation' })
      }
    }
  }
  
});

//login route
app.post('/login', async function(req, res, next) {
  const { name, password } = req.body; //1
  if (name && password) {
    let user = await getUser({ name: name });
    if (!user) {
      res.status(401).json({ message: 'No such user found' });
    }
    
    const check = await bcrypt.compare(password, user.password);
    
    if (check) {
      // from now on we'll identify the user by the id and the id is the 
      // only personalized value that goes into our token
      let payload = { id: user.id };
      let token = jwt.sign(payload, jwtOptions.secretOrKey, {
        expiresIn: '1h'
      });
      // res.cookie('token', token, { httpOnly: true }).sendStatus(200);
      // next();
      res.json({ msg: 'ok', token: token });
    } else {
      res.status(401).json({ msg: 'Password is incorrect' });
    }
  }
});


// Дать ключи
app.post('/ss33sh', withAuth, function(req, res) {
  res.send({
    api: '5dec5986d30fb2dc1a92bb6d1e055447a359f0590e6794706eb991bbb4eab090',
    apiG: 'fb0d5699bd8145b68ec866138df4a623',
    mapbox: 'pk.eyJ1IjoiZ2xvcnlmcnMiLCJhIjoiY2p5eHZtdm05MWJjaDNtcnJxY3UwdnYwOCJ9.VhGilGU54k8Voi0pIaVggQ'
  });
});


// Токен
app.post('/checkToken', withAuth, function(req, res) {
  res.sendStatus(200);
});
app.post('/checkAdmin', async function(req, res) {
  const decoded = await jwt.verify(req.body.token, 'wowwow');
  if(decoded.id == 74) {
    res.sendStatus(200);
  }else {
    res.sendStatus(401);
  }
  
});
app.post("/getUser", async (req, res, next) => {
  const usertoken = req.body.token;
  
  try {
    const decoded = await jwt.verify(usertoken, 'wowwow');
    let user = await getUser({ id: decoded.id });
    const params = new URLSearchParams();
    params.append('id', user.name);
    const resAxios = await axios.post("https://vk.masterimodel.com/node/masters.get", params)
    res.send(resAxios.data);
  } catch (error) {
    try {
      const decoded = await jwt.verify(usertoken, 'wowwow');
      let user = await getUser({ name: decoded.id });
      const params = new URLSearchParams();
      params.append('id', user.name);
      const resAxios = await axios.post("https://vk.masterimodel.com/node/masters.get", params)
      res.send(resAxios.data);
    } catch (error) {
      res.send({access: false})  
    }
    
  }
})
// вк авторизация (через сервис 0auth)

app.post("/vkauth", async (req, res, next) => {
  if (req.body.id) {
    let payload = { id: req.body.id };
    let token = jwt.sign(payload, jwtOptions.secretOrKey, {
      expiresIn: '1h'
    });
    const decoded = await jwt.verify(token, 'wowwow');
    
    res.send({'token': token});
  } else {
    res.send({'err': 'err'});
  }
  
})
// вк авторизация (через паспорт)

app.get('/auth/vkontakte', passport.authenticate('vkontakte'));

app.get('/auth/vkontakte/callback',
  passport.authenticate('vkontakte', {
    failureRedirect: 'https://lk.masterimodel.app/card/7296096' 
  }), async (req, res) => {
    if (req.user.id){
      let payload = { id: req.user.id };
      let token = jwt.sign(payload, jwtOptions.secretOrKey, {
        expiresIn: '1h'
      });
      const decoded = await jwt.verify(token, 'wowwow');
      res.redirect('https://lk.masterimodel.app/profile?token='+ token);
    } else {
      res.send({'err': 'err'});
    }
    
    
  }
);

let httpServer = http.createServer(app);
let httpsServer = https.createServer(credentials, app);

httpServer.listen(3004, function () {
  console.log(`We live on 3004 port HTTP`);
});
httpsServer.listen(3005, function () {
  console.log(`We live on 3005 port HTTPS`);
});