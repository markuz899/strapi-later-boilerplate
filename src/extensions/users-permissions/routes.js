// routes.js
module.exports = (plugin) => {
  // AUTH ROUTES
  plugin.routes["content-api"].routes.push({
    method: "POST",
    path: "/auth/login",
    handler: "user.login",
    config: {
      prefix: "",
    },
  });

  plugin.routes["content-api"].routes.push({
    method: "POST",
    path: "/auth/register",
    handler: "user.register",
    config: {
      prefix: "",
    },
  });

  plugin.routes["content-api"].routes.push({
    method: "POST",
    path: "/auth/change-password",
    handler: "user.changePassword",
    config: {
      prefix: "",
    },
  });

  plugin.routes["content-api"].routes.push({
    method: "POST",
    path: "/auth/reset-password",
    handler: "user.resetPassword",
    config: {
      prefix: "",
    },
  });

  plugin.routes["content-api"].routes.push({
    method: "POST",
    path: "/auth/forgot-password",
    handler: "user.forgotPassword",
    config: {
      prefix: "",
    },
  });

  // USER ROUTES
  plugin.routes["content-api"].routes.push({
    method: "PUT",
    path: "/user/update",
    handler: "user.update",
    config: {
      prefix: "",
    },
  });

  plugin.routes["content-api"].routes.push({
    method: "GET",
    path: "/user/me",
    handler: "user.me",
    config: {
      prefix: "",
    },
  });

  plugin.routes["content-api"].routes.push({
    method: "GET",
    path: "/users/",
    handler: "user.find",
    config: {
      prefix: "",
    },
  });

  plugin.routes["content-api"].routes.push({
    method: "GET",
    path: "/user/:id",
    handler: "user.findOne",
    config: {
      prefix: "",
    },
  });
};
