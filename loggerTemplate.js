const winston = require('winston');

const { createLogger, transports, format } = require('winston');

//Logger Template that prints your log output onto the console and log files in a particular format
//Apart from the console output, it outputs all logs into the 'infoLog.log' file and error logs specifically into the 'error.log' file

const logger = winston.createLogger({
    transports: [
      new winston.transports.File({
        filename: 'infoLog.log',
        level: 'info',
        format: format.combine(format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }), format.errors({ stack: true }), format.splat(), format.json())
      }),
      new winston.transports.File({
        filename: 'error.log',
        level: 'error',
        format: format.combine(format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }), format.errors({ stack: true }), format.splat(), format.json())
      }),
      new transports.Console({
        level: 'error',
        format: format.combine(format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }), format.errors({ stack: true }), format.splat(), format.json())
      }),
      new transports.Console({
        level: 'warn',
        format: format.combine(format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }), format.errors({ stack: true }), format.splat(), format.json())
      }),
      new transports.Console({
        level: 'info',
        format: format.combine(format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }), format.errors({ stack: true }), format.splat(), format.json())
      })
    ]
});


function loggerTemplate (param1, param2 = "", param3 = "") {
    //param1 is Log Level -> "error", "warn", "info" (default is "info")
    //param2 is Error/Warn/Info Location
    //param3 is Log Details (Can be OBJECT)

    var param3String = "";
    if ((typeof(param3) === 'object') && (param3 !== null)){
      for (const property in param3) {
        param3String += ` ${property} -> ${param3[property]} ,`;
      }
    }
    else {
      param3String = param3;
    }

    if(typeof(param1) === "string"){
        param1 = param1.toLowerCase();
        switch(param1) {

            case "error": {
                logger.log('error', `Error at Location: ${param2} | Details are as follows: ${param3String}`);
            } break;

            case "warn": {
                logger.log('warn', `Warning at Location: ${param2} | Details are as follows: ${param3String}`);
            } break;

            case "info": {
                logger.log('info', `Information Log at Location: ${param2} | Details are as follows: ${param3String}`);
            } break;

            default: {
                logger.log('info', `Custom Log Level: ${param1} | Log at Location: ${param2} | Details are as follows: ${param3String}`);
            } break;
        }
    }
    else { 
        logger.log('info', `${param1} | ${param2} | ${param3String}`);
    }
}

//Example below: 

// loggerTemplate("error", "Authentication", "Please enter the correct username and password");

module.exports = loggerTemplate;