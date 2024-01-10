// @ts-nocheck

/* eslint-disable no-useless-escape */
const crypto = require("crypto");
const _ = require("lodash");
const { concat, compact, isArray } = require("lodash/fp");
const utils = require("@strapi/utils");
const {
  contentTypes: { getNonWritableAttributes },
} = require("@strapi/utils");
const {
  validateCallbackBody,
  validateRegisterBody,
  validateSendEmailConfirmationBody,
  validateForgotPasswordBody,
  validateResetPasswordBody,
  validateEmailConfirmationBody,
  validateChangePasswordBody,
} = require("./validation/auth");
const { validateUpdateUserBody } = require("./validation/user");

const { getAbsoluteAdminUrl, getAbsoluteServerUrl, sanitize, validate } = utils;
const { ApplicationError, ValidationError, ForbiddenError, NotFoundError } =
  utils.errors;

const sanitizeUser = (user, ctx) => {
  const { auth } = ctx.state;
  const userSchema = strapi.getModel("plugin::users-permissions.user");

  return sanitize.contentAPI.output(user, userSchema, { auth });
};

const sanitizeOutput = async (user, ctx) => {
  const schema = strapi.getModel("plugin::users-permissions.user");
  const { auth } = ctx.state;

  return sanitize.contentAPI.output(user, schema, { auth });
};

const validateQuery = async (query, ctx) => {
  const schema = strapi.getModel("plugin::users-permissions.user");
  const { auth } = ctx.state;

  return validate.contentAPI.query(query, schema, { auth });
};

const sanitizeQuery = async (query, ctx) => {
  const schema = strapi.getModel("plugin::users-permissions.user");
  const { auth } = ctx.state;

  return sanitize.contentAPI.query(query, schema, { auth });
};

const getService = (name) => {
  return strapi.plugin("users-permissions").service(name);
};

module.exports = (plugin) => {
  // AUTH CONTROLLER

  plugin.controllers.user.login = async (ctx) => {
    console.log("NUOVO CONTROLLER PD");
    const provider = ctx.params.provider || "local";
    const params = ctx.request.body;

    const store = strapi.store({ type: "plugin", name: "users-permissions" });
    const grantSettings = await store.get({ key: "grant" });

    const grantProvider = provider === "local" ? "email" : provider;

    if (!_.get(grantSettings, [grantProvider, "enabled"])) {
      throw new ApplicationError("This provider is disabled");
    }

    if (provider === "local") {
      await validateCallbackBody(params);

      const { identifier } = params;

      // Check if the user exists.
      const user = await strapi
        .query("plugin::users-permissions.user")
        .findOne({
          where: {
            provider,
            $or: [
              { email: identifier.toLowerCase() },
              { username: identifier },
            ],
          },
        });

      if (!user) {
        throw new ValidationError("Invalid identifier or password");
      }

      if (!user.password) {
        throw new ValidationError("Invalid identifier or password");
      }

      const validPassword = await getService("user").validatePassword(
        params.password,
        user.password
      );

      if (!validPassword) {
        throw new ValidationError("Invalid identifier or password");
      }

      const advancedSettings = await store.get({ key: "advanced" });
      const requiresConfirmation = _.get(
        advancedSettings,
        "email_confirmation"
      );

      if (requiresConfirmation && user.confirmed !== true) {
        throw new ApplicationError("Your account email is not confirmed");
      }

      if (user.blocked === true) {
        throw new ApplicationError(
          "Your account has been blocked by an administrator"
        );
      }

      return ctx.send({
        jwt: getService("jwt").issue({ id: user.id }),
        user: await sanitizeUser(user, ctx),
      });
    }

    // Connect the user with the third-party provider.
    try {
      const user = await getService("providers").connect(provider, ctx.query);

      if (user.blocked) {
        throw new ForbiddenError(
          "Your account has been blocked by an administrator"
        );
      }

      return ctx.send({
        jwt: getService("jwt").issue({ id: user.id }),
        user: await sanitizeUser(user, ctx),
      });
    } catch (error) {
      throw new ApplicationError(error.message);
    }
  };

  plugin.controllers.user.register = async (ctx) => {
    const pluginStore = await strapi.store({
      type: "plugin",
      name: "users-permissions",
    });

    const settings = await pluginStore.get({ key: "advanced" });

    //@ts-ignore
    if (!settings.allow_register) {
      throw new ApplicationError("Register action is currently disabled");
    }

    //@ts-ignore
    const { register } = strapi.config.get("plugin.users-permissions");
    const alwaysAllowedKeys = ["username", "password", "email"];
    const userModel = strapi.contentTypes["plugin::users-permissions.user"];
    const { attributes } = userModel;

    const nonWritable = getNonWritableAttributes(userModel);

    const allowedKeys = compact(
      concat(
        alwaysAllowedKeys,
        isArray(register?.allowedFields)
          ? // Note that we do not filter allowedFields in case a user explicitly chooses to allow a private or otherwise omitted field on registration
            register.allowedFields // if null or undefined, compact will remove it
          : // to prevent breaking changes, if allowedFields is not set in config, we only remove private and known dangerous user schema fields
            // TODO V5: allowedFields defaults to [] when undefined and remove this case
            Object.keys(attributes).filter(
              (key) =>
                !nonWritable.includes(key) &&
                //@ts-ignore
                !attributes[key].private &&
                ![
                  // many of these are included in nonWritable, but we'll list them again to be safe and since we're removing this code in v5 anyway
                  // Strapi user schema fields
                  "confirmed",
                  "blocked",
                  "confirmationToken",
                  "resetPasswordToken",
                  "provider",
                  "id",
                  "role",
                  // other Strapi fields that might be added
                  "createdAt",
                  "updatedAt",
                  "createdBy",
                  "updatedBy",
                  "publishedAt", // d&p
                  "strapi_reviewWorkflows_stage", // review workflows
                ].includes(key)
            )
      )
    );

    const params = {
      ..._.pick(ctx.request.body, allowedKeys),
      provider: "local",
    };

    await validateRegisterBody(params);

    const role = await strapi
      .query("plugin::users-permissions.role")
      //@ts-ignore
      .findOne({ where: { type: settings.default_role } });

    if (!role) {
      throw new ApplicationError("Impossible to find the default role");
    }

    //@ts-ignore
    const { email, username, provider } = params;

    const identifierFilter = {
      $or: [
        { email: email.toLowerCase() },
        { username: email.toLowerCase() },
        { username },
        { email: username },
      ],
    };

    const conflictingUserCount = await strapi
      .query("plugin::users-permissions.user")
      .count({
        where: { ...identifierFilter, provider },
      });

    if (conflictingUserCount > 0) {
      throw new ApplicationError("Email or Username are already taken");
    }

    //@ts-ignore
    if (settings.unique_email) {
      const conflictingUserCount = await strapi
        .query("plugin::users-permissions.user")
        .count({
          where: { ...identifierFilter },
        });

      if (conflictingUserCount > 0) {
        throw new ApplicationError("Email or Username are already taken");
      }
    }

    const newUser = {
      ...params,
      role: role.id,
      email: email.toLowerCase(),
      username,
      //@ts-ignore
      confirmed: !settings.email_confirmation,
    };

    const user = await getService("user").add(newUser);

    const sanitizedUser = await sanitizeUser(user, ctx);

    //@ts-ignore
    if (settings.email_confirmation) {
      try {
        await getService("user").sendConfirmationEmail(sanitizedUser);
      } catch (err) {
        throw new ApplicationError(err.message);
      }

      return ctx.send({ user: sanitizedUser });
    }

    const jwt = getService("jwt").issue(_.pick(user, ["id"]));

    return ctx.send({
      jwt,
      user: sanitizedUser,
    });
  };

  plugin.controllers.user.changePassword = async (ctx) => {
    if (!ctx.state.user) {
      throw new ApplicationError(
        "You must be authenticated to reset your password"
      );
    }

    const { currentPassword, password } = await validateChangePasswordBody(
      ctx.request.body
    );

    const user = await strapi.entityService.findOne(
      "plugin::users-permissions.user",
      ctx.state.user.id
    );

    const validPassword = await getService("user").validatePassword(
      currentPassword,
      user.password
    );

    if (!validPassword) {
      throw new ValidationError("The provided current password is invalid");
    }

    if (currentPassword === password) {
      throw new ValidationError(
        "Your new password must be different than your current password"
      );
    }

    await getService("user").edit(user.id, { password });

    ctx.send({
      jwt: getService("jwt").issue({ id: user.id }),
      user: await sanitizeUser(user, ctx),
    });
  };

  plugin.controllers.user.resetPassword = async (ctx) => {
    const { password, passwordConfirmation, code } =
      await validateResetPasswordBody(ctx.request.body);

    if (password !== passwordConfirmation) {
      throw new ValidationError("Passwords do not match");
    }

    const user = await strapi
      .query("plugin::users-permissions.user")
      .findOne({ where: { resetPasswordToken: code } });

    if (!user) {
      throw new ValidationError("Incorrect code provided");
    }

    await getService("user").edit(user.id, {
      resetPasswordToken: null,
      password,
    });

    // Update the user.
    ctx.send({
      jwt: getService("jwt").issue({ id: user.id }),
      user: await sanitizeUser(user, ctx),
    });
  };

  plugin.controllers.user.forgotPassword = async (ctx) => {
    const { email } = await validateForgotPasswordBody(ctx.request.body);

    const pluginStore = await strapi.store({
      type: "plugin",
      name: "users-permissions",
    });

    const emailSettings = await pluginStore.get({ key: "email" });
    const advancedSettings = await pluginStore.get({ key: "advanced" });

    // Find the user by email.
    const user = await strapi
      .query("plugin::users-permissions.user")
      .findOne({ where: { email: email.toLowerCase() } });

    if (!user || user.blocked) {
      return ctx.send({ ok: true });
    }

    // Generate random token.
    const userInfo = await sanitizeUser(user, ctx);

    const resetPasswordToken = crypto.randomBytes(64).toString("hex");

    const resetPasswordSettings = _.get(
      emailSettings,
      "reset_password.options",
      {}
    );
    const emailBody = await getService("users-permissions").template(
      resetPasswordSettings.message,
      {
        URL: advancedSettings.email_reset_password,
        SERVER_URL: getAbsoluteServerUrl(strapi.config),
        ADMIN_URL: getAbsoluteAdminUrl(strapi.config),
        USER: userInfo,
        TOKEN: resetPasswordToken,
      }
    );

    const emailObject = await getService("users-permissions").template(
      resetPasswordSettings.object,
      {
        USER: userInfo,
      }
    );

    const emailToSend = {
      to: user.email,
      from:
        resetPasswordSettings.from.email || resetPasswordSettings.from.name
          ? `${resetPasswordSettings.from.name} <${resetPasswordSettings.from.email}>`
          : undefined,
      replyTo: resetPasswordSettings.response_email,
      subject: emailObject,
      text: emailBody,
      html: emailBody,
    };

    // NOTE: Update the user before sending the email so an Admin can generate the link if the email fails
    await getService("user").edit(user.id, { resetPasswordToken });

    // Send an email to the user.
    await strapi.plugin("email").service("email").send(emailToSend);

    ctx.send({ ok: true });
  };

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

  // USER CONTROLLER

  plugin.controllers.user.update = async (ctx) => {
    const authUser = ctx.state.user;
    const advancedConfigs = await strapi
      .store({ type: "plugin", name: "users-permissions", key: "advanced" })
      .get();

    const { email, username, password } = ctx.request.body;

    const user = await getService("user").fetch(authUser.id);
    if (!user) {
      throw new NotFoundError(`User not found`);
    }

    await validateUpdateUserBody(ctx.request.body);

    if (
      user.provider === "local" &&
      _.has(ctx.request.body, "password") &&
      !password
    ) {
      throw new ValidationError("password.notNull");
    }

    if (_.has(ctx.request.body, "username")) {
      const userWithSameUsername = await strapi
        .query("plugin::users-permissions.user")
        .findOne({ where: { username } });

      if (
        userWithSameUsername &&
        _.toString(userWithSameUsername.id) !== _.toString(authUser.id)
      ) {
        throw new ApplicationError("Username already taken");
      }
    }

    if (_.has(ctx.request.body, "email") && advancedConfigs.unique_email) {
      const userWithSameEmail = await strapi
        .query("plugin::users-permissions.user")
        .findOne({ where: { email: email.toLowerCase() } });

      if (
        userWithSameEmail &&
        _.toString(userWithSameEmail.id) !== _.toString(authUser.id)
      ) {
        throw new ApplicationError("Email already taken");
      }
      ctx.request.body.email = ctx.request.body.email.toLowerCase();
    }

    const updateData = {
      ...ctx.request.body,
    };

    const data = await getService("user").edit(user.id, updateData);
    const sanitizedData = await sanitizeOutput(data, ctx);

    ctx.send(sanitizedData);
  };

  plugin.controllers.user.me = async (ctx) => {
    const authUser = ctx.state.user;
    const { query } = ctx;

    if (!authUser) {
      return ctx.unauthorized();
    }

    await validateQuery(query, ctx);
    const sanitizedQuery = await sanitizeQuery(query, ctx);
    const user = await getService("user").fetch(authUser.id, sanitizedQuery);

    ctx.body = await sanitizeOutput(user, ctx);
  };

  plugin.controllers.user.find = async (ctx) => {
    await validateQuery(ctx.query, ctx);
    const sanitizedQuery = await sanitizeQuery(ctx.query, ctx);
    const users = await getService("user").fetchAll(sanitizedQuery);

    ctx.body = await Promise.all(
      users.map((user) => sanitizeOutput(user, ctx))
    );
  };

  plugin.controllers.user.findOne = async (ctx) => {
    const { id } = ctx.params;
    await validateQuery(ctx.query, ctx);
    const sanitizedQuery = await sanitizeQuery(ctx.query, ctx);

    let data = await getService("user").fetch(id, sanitizedQuery);

    if (data) {
      data = await sanitizeOutput(data, ctx);
    }

    ctx.body = data;
  };

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

  return plugin;
};
