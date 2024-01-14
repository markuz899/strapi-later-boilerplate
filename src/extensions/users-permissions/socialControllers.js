// @ts-nocheck
/* eslint-disable no-useless-escape */
const _ = require("lodash");
const { concat, compact, isArray } = require("lodash/fp");
const utils = require("@strapi/utils");
const axios = require("axios");
const {
  contentTypes: { getNonWritableAttributes },
} = require("@strapi/utils");
const { validateRegisterBody } = require("./validation/auth");

const { sanitize } = utils;
const { ApplicationError } = utils.errors;

const sanitizeUser = (user, ctx) => {
  const { auth } = ctx.state;
  const userSchema = strapi.getModel("plugin::users-permissions.user");

  return sanitize.contentAPI.output(user, userSchema, { auth });
};

const getService = (name) => {
  return strapi.plugin("users-permissions").service(name);
};

const generateRandomPassword = () => {
  const charset =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  let password = "";

  for (let i = 0; i < 8; i++) {
    const randomIndex = Math.floor(Math.random() * charset.length);
    password += charset.charAt(randomIndex);
  }

  return password;
};

module.exports = (plugin) => {
  // SOCIAL CONTROLLER

  plugin.controllers.user.socialOauthRedirect = async (ctx) => {
    const { social } = ctx.query;

    const SOCIAL = {
      facebook: `https://www.facebook.com/v14.0/dialog/oauth?client_id=${process.env.FACEBOOK_APP_ID}&redirect_uri=${process.env.FRONTEND_URL}/auth/facebook/callback&scope=email`,
      google: `https://accounts.google.com/o/oauth2/auth?client_id=${process.env.GOOGLE_APP_ID}&redirect_uri=${process.env.FRONTEND_URL}/auth/google/callback&response_type=code&scope=profile%20email`,
    };

    ctx.send({ redirectUrl: SOCIAL[social] });
  };

  plugin.controllers.user.socialOauthCallback = async (ctx) => {
    const { social, code } = ctx.query;

    const SOCIAL = {
      facebook: `https://graph.facebook.com/v14.0/oauth/access_token?client_id=${process.env.FACEBOOK_APP_ID}&redirect_uri=${process.env.FRONTEND_URL}/auth/facebook/callback&client_secret=${process.env.FACEBOOK_SECRET_APP_ID}&code=${code}`,
      google: `https://oauth2.googleapis.com/token`,
    };

    try {
      let userData = null;

      if (social == "facebook") {
        const response = await axios.get(SOCIAL[social]);
        const accessToken = response.data.access_token;

        const userInfoUrl = `https://graph.facebook.com/me?fields=id,name,email&access_token=${accessToken}`;
        const userResponse = await axios.get(userInfoUrl);
        userData = userResponse.data;
      } else {
        const params = new URLSearchParams();
        params.append("code", code);
        params.append("client_id", process.env.GOOGLE_APP_ID);
        params.append("client_secret", process.env.GOOGLE_SECRET_APP_ID);
        params.append(
          "redirect_uri",
          `${process.env.FRONTEND_URL}/auth/google/callback`
        );
        params.append("grant_type", "authorization_code");
        const response = await axios.post(SOCIAL[social], params);
        const accessToken = response.data.access_token;

        // Usa il token di accesso per ottenere le informazioni dell'utente
        const userInfoUrl = `https://www.googleapis.com/oauth2/v3/userinfo?access_token=${accessToken}`;
        const userResponse = await axios.get(userInfoUrl);
        userData = userResponse.data;
      }

      const user = {
        email: userData?.email,
        username: userData?.email,
        name: userData?.name.split(" ")[0],
        surname: userData?.name.split(" ")[1],
        password: generateRandomPassword(),
      };

      // check user alredy exist
      const identyFilter = {
        $or: [
          { email: user?.email.toLowerCase() },
          { username: user?.email.toLowerCase() },
          { email: user?.username },
        ],
      };

      const userExist = await strapi
        .query("plugin::users-permissions.user")
        .findOne({
          where: identyFilter,
        });

      if (userExist) {
        if (userExist.blocked === true) {
          strapi.log.error("Your account has been blocked by an administrator");
          throw new ApplicationError(
            "Your account has been blocked by an administrator"
          );
        }

        return ctx.send({
          jwt: getService("jwt").issue({ id: userExist.id }),
          user: await sanitizeUser(userExist, ctx),
        });
      }

      // register client
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
        ..._.pick(user, allowedKeys),
        provider: "local",
      };

      await validateRegisterBody(params);

      const role = await strapi
        .query("plugin::users-permissions.role")
        //@ts-ignore
        .findOne({ where: { type: settings.default_role } });

      if (!role) {
        strapi.log.error("Impossible to find the default role");
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
        strapi.log.error("Email or Username are already taken");
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
          strapi.log.error("Email or Username are already taken");
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

      const userInfo = await getService("user").add(newUser);

      const sanitizedUser = await sanitizeUser(userInfo, ctx);

      //@ts-ignore
      if (settings.email_confirmation) {
        try {
          await getService("user").sendConfirmationEmail(sanitizedUser);
        } catch (err) {
          strapi.log.error(err.message);
          throw new ApplicationError(err.message);
        }

        return ctx.send({ user: sanitizedUser });
      }

      const jwt = getService("jwt").issue(_.pick(userInfo, ["id"]));

      return ctx.send({
        jwt,
        user: sanitizedUser,
      });
    } catch (error) {
      console.error(error);
      throw new ApplicationError("Error during oauth with Facebook");
    }
  };
};
