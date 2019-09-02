const authRoutes = require('./authRoutes');

module.exports = function (app, withAuth, createUser, getAllUsers, getUser, updateUser, jwtOptions) {
  authRoutes(app, withAuth, createUser, getAllUsers, getUser, updateUser, jwtOptions);
  //another routes
};