const mongoose = require("mongoose");

//const MONGOURI = "mongodb://raunak:mokhasi@logincluster-shard-00-00-v0ove.mongodb.net:27017,logincluster-shard-00-01-v0ove.mongodb.net:27017,logincluster-shard-00-02-v0ove.mongodb.net:27017/mongoLoginDB?ssl=true&replicaSet=loginCluster-shard-0&authSource=admin&retryWrites=true&w=majority";

const MONGOURI = "mongodb://localhost:27017/collaboration"
const logger = require("./winstonLogger");

const InitiateMongoServer = async () => {   //async ensures that the function returns a promise (eventual completion/failure of an operation), and wraps non-promises in it
  try {
    await mongoose.connect(MONGOURI, { useNewUrlParser: true });  //await makes JavaScript wait until that promise settles and returns its result
    logger.log('info',"Successfully connected to MongoDB");
  } 
  catch (e) {
    //console.log(e);
    logger.log('error', new Error(e));
    throw e;
  }
};

//console.log(JSON.stringify(process.env.NODE_ENV));

if (process.env.NODE_ENV === 'test') {
  console.log("MOCKING");
  var Mockgoose = require('mockgoose').Mockgoose;
  var mockgoose = new Mockgoose(mongoose);
  mockgoose.prepareStorage().then(function() {
    const InitiateMongoServer = async () => {
      try {
        await mongoose.connect(MONGOURI, { useNewUrlParser: true });
        //console.log("Successfully connected to MOCK-GOOSE");
        logger.log('info',"Successfully connected to MOCK-GOOSE");
      } 
      catch (e) {
        //console.log(e);
        logger.log('error', new Error(e));
        throw e;
      }
    };		
  });
}

module.exports = InitiateMongoServer;