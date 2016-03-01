var winston = require('winston');
var winstonAmqp = require('winston-amqp');

var amqpHost = process.env.AMQP_HOST || 'amqp://wcvabgeb:rfTHtEtqA1GtFe6M_32oIJ6OG-YflqWm@chicken.rmq.cloudamqp.com/wcvabgeb';

winston.emitErrs = true;
var logger = new winston.Logger({
    transports: [
        new winston.transports.Console({
            timestamp: true,
            level: process.env.GATEWAY_LOG_LEVEL || 'debug',
            handleExceptions: false,
            json: false,
            colorize: true
        }),
        new winstonAmqp.AMQP({
            name: 'gateway',
            level: process.env.GATEWAY_LOG_LEVEL || 'debug',
            host: amqpHost,
            exchange: 'log',
            routingKey: 'gateway'
        })
    ],
    exitOnError: false
});

logger.stream = {
    write: function(message, encoding) {
        logger.debug(message.replace(/\n$/, ''));
    }
};

module.exports = logger;