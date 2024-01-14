module.exports = {
  apps: [
    {
      name: "CMS-Unidealer",
      script: "npm",
      args: "start",
      istances: "max",
      exec_mode: "cluster",
      autorestart: true,
      max_memory_restart: "500M",
      delay: 1000,
      env: {
        NODE_ENV: "production",
      },
    },
  ],
};
