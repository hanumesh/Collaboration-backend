//Winston Code

const winston = require('winston');

const { createLogger, transports, format } = require('winston');

const logger = winston.createLogger({
    transports: [
      new winston.transports.File({
        filename: 'infoLog.log',
        level: 'info',
        format: format.combine(format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }), format.errors({ stack: true }), format.splat(),format.json())
      }),
      new winston.transports.File({
        filename: 'error.log',
        level: 'error',
        format: format.combine(format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }), format.errors({ stack: true }), format.splat(),format.json())
      }),
      new transports.Http({
        level: 'warn',
        format: format.combine(format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }), format.errors({ stack: true }), format.splat(),format.json())
      }),
      new transports.Console({
        level: 'info',
        format: format.combine(format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }), format.errors({ stack: true }), format.splat(),format.json())
      })
    ]
});


module.exports = logger;


/* For Daily Logging -
// DO - npm install winston-daily-rotate-file
const winston = require('winston')
require('winston-daily-rotate-file');
const path = require('path');
let transports  = [];
const { createLogger } = winston;
transports.push(
    new winston.transports.DailyRotateFile({
      name: 'file',
      datePattern: 'YYYY-MM-DD-THH-mm',
      filename: path.join(__dirname, 'rotate_logs', 'log_file.log')
    })
)

const dailyLogger = winston.createLogger({
    transports: [
        new winston.transports.DailyRotateFile ({
            filename: 'application-%DATE%.log',
            level: 'info',
            datePattern: 'YYYY-MM-DD-HH',
            zippedArchive: true,
            maxSize: '20m',
            maxFiles: '14d'        
        })
    ],
    exitOnError: false
});

dailyLogger.stream = {
    write: function(message, encoding) {
      logger.info(message);
    },
};

export default logger;
*/