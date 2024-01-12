module.exports = [
  "strapi::logger",
  "strapi::errors",
  "strapi::security",
  // 'strapi::cors',
  "strapi::poweredBy",
  "strapi::query",
  "strapi::body",
  "strapi::session",
  "strapi::favicon",
  "strapi::public",
  {
    name: "strapi::cors",
    config: {
      enabled: false,
      headers: "*",
      origin: ["http://localhost:3000", "*"],
    },
  },
];
