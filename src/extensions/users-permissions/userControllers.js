// @ts-nocheck
/* eslint-disable no-useless-escape */
const _ = require("lodash");
const utils = require("@strapi/utils");
const { validateUpdateUserBody } = require("./validation/user");

const { sanitize, validate } = utils;
const { ApplicationError, ValidationError, NotFoundError } = utils.errors;

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
};
