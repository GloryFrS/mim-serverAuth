const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const axios = require('axios');

module.exports = function(app, withAuth, createUser, getAllUsers, getUser, updateUser, jwtOptions) {
    // get all users
    app.get('/users', function(req, res) {
        getAllUsers().then(user => res.json(user));
    });
    
    // register route
    app.post('/register', async function(req, res, next) {
        let { name, password } = req.body;
        const saltRounds = 10;
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
            }else {
            res.json({msg: 'err validation' })
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
        console.log(user);
        
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
    // вк авторизация
    app.post("/vkauth", async (req, res, next) => {
        if (req.body.id) {
            let payload = { id: req.body.id };
            let token = jwt.sign(payload, jwtOptions.secretOrKey, {
            expiresIn: '1h'
            });
            const decoded = await jwt.verify(token, 'wowwow');
            console.log(decoded, "asdasds");
        
            res.send({'token': token});
        } else {
            res.send({'err': 'err'});
        }
    })
  
  }