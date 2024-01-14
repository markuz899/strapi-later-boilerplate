// routes.js
module.exports = (plugin) => {
  // SOCIAL ROUTES
  plugin.routes["content-api"].routes.push({
    method: "GET",
    path: "/social/user/auth",
    handler: "user.socialOauthRedirect",
    config: {
      prefix: "",
    },
  });

  plugin.routes["content-api"].routes.push({
    method: "GET",
    path: "/social/user/callback",
    handler: "user.socialOauthCallback",
    config: {
      prefix: "",
    },
  });

  // AUTH ROUTES
  plugin.routes["content-api"].routes.push({
    method: "POST",
    path: "/auth/user/login",
    handler: "user.login",
    config: {
      prefix: "",
    },
  });

  plugin.routes["content-api"].routes.push({
    method: "POST",
    path: "/auth/user/register",
    handler: "user.register",
    config: {
      prefix: "",
    },
  });

  plugin.routes["content-api"].routes.push({
    method: "POST",
    path: "/auth/user/change-password",
    handler: "user.changePassword",
    config: {
      prefix: "",
    },
  });

  plugin.routes["content-api"].routes.push({
    method: "POST",
    path: "/auth/user/reset-password",
    handler: "user.resetPassword",
    config: {
      prefix: "",
    },
  });

  plugin.routes["content-api"].routes.push({
    method: "POST",
    path: "/auth/user/forgot-password",
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
