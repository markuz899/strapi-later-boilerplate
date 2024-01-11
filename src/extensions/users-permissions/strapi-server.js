// server.js

/* eslint-disable no-useless-escape */
const routes = require("./routes");
const authControllers = require("./authControllers");
const userControllers = require("./userControllers");

module.exports = (plugin) => {
  routes(plugin), authControllers(plugin), userControllers(plugin);
  return plugin;
};
