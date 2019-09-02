

module.exports = function () { 
    // initialze an instance of Sequelize
    
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
}
module.exports = mongoose.model('users', schema);

// create table with user model
module.exports = db = User.sync()
  .then(() => console.log('User table created successfully'))
  .catch(err => console.log('oooh, did you enter wrong database credentials?'));