//BUNYAN CODE
const path = require("path");
const bunyan = require("bunyan");
const level = process.env.NODE_LOGGING_LEVEL || "info";

const bunyanLog = bunyan.createLogger({
  name: "LoginAuthentication",
  serializers: {
    req: bunyan.stdSerializers.req,
    res: bunyan.stdSerializers.res,
    err: bunyan.stdSerializers.err
  },
  level: 'info',
  streams: [
    {
      level,
      stream: process.stdout
    },
    {
      level,
      path: path.resolve(__dirname, "..", "..", "bunyanLogs.json")
    }
  ]
});

module.exports = bunyanLog