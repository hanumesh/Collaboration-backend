**Description of API-**

This is a Collboration API built using Express (minimal and flexible Node.js web application framework) and MongoDB as the Database. We are using the Express-Validator that prevents requests which include invalid username or password. We are also using bcryptjs as a secure method to store passwords in Database using Encryption Techniques (Generating salt and hashing). In addition to these, jsonwebtoken is used as a secure method to transmit information between parties as a JSON object with a Digital Signature.

_Note – Use the command &#39;npm i express mongoose mockgoose chai mocha winston supertest express-validator body-parser bcryptjs jsonwebtoken &#39; to install the dependencies._

_In order to run the code just use the command &quot;npm run start&quot; on your Bash Terminal._
_(In order to run the tests, use teh command &quot;npm run test&quot; on your Bash Terminal. We have used Mockgoose to mock the operations of the database)_

_Make sure you change the value of the_ _ **MONGOURI** _ _in the db.js file with your MongoDB Definitions (database name, username and password)._

- The site is setup on &#39;localhost:4000&#39;

- The &quot;swagger&quot; Route is used to see a complete documentation of the Code using Swagger.

- The &quot;signup&quot; Route is used to add a new user to the database.

The Signup method takes in username, email and password. It checks the username and password for invalid characters and also checks if the password has a minimum length of 5. The password is encrypted using salting and hashing to ensure secure saving of information.

The User object is then saved into the database with the data entered of username, email and password. An additional CreatedAt attribute is added to the object denoting the date and time of creation of the user account.

It returns the TokenID generated after signing up the user.

- The &quot;login&quot; Route is used to Login an existing user from the database.
- It takes in the Email ID and Password of the User and verifies if it exists in the database with the given credentials. It returns the TokenID generated after logging in the user.

- The &quot;getUserInfo&quot; Route is used to retrieve information about a user from the Database by using the input parameter of Token ID that is received after signup or login of the user. This then returns the User Object from the Database containing details such as Username, EmailID, Password and CreatedAt.

**SWAGGER Documentation -**

1. Swagger is a popular API documentation tool that not only lets you explain your code for future users, but also allows them to access and experiment with the APIs.

2. On completion of the code, we can use the Swagger Online Editor to document it. Swagger provides the [http://editor.swagger.io/](http://editor.swagger.io/) which can be used to quickly configure the YAML definitions. You can either write the documentation directly in JSON format or write it in YAML and then convert it to JSON through this website. I personally followed the latter as I found it easier.

![Alt text](https://github.com/raunakmokhasi/LoginAuthenticationAPI/blob/master/Screens/SwaggerScreen1.JPG?raw=true "Online Swagger Editor")

3. Swagger generates the documentation for the API using a simple YAML file that describes your API (routes, verbs, params and other definitions). This YAML file can then later be converted into JSON format to be integrated with your APIs on your local machine. The YAML file has tags used to describe each function of the API and is really intuitive to understand.

  To integrate the YAML/JSON files with our code we need to follow the following steps -

  On your local terminal (in my case I used the Bash Terminal on Visual Studio Code), use the command &quot;npm i swagger-jsdoc swagger-  ui-express&quot;. This gives us two different methods to document our code using Swagger.

  The &#39;swagger-jsdoc&#39; is used to integrate Swagger using JSDoc Comments in the code. We need to add @swagger on top of a subroutine (for example the POST Request for /signup) and declare the meaning of your code in YAML complying to the OpenAPI specification). The &#39;swagger-jsdoc&#39; will then parse this and output an OpenAPI specification which can be used to integrate any server and client technology as long as both sides comply with the specification.

  The &#39;swagger-ui-express&#39; is a module that allows you to serve auto-generated swagger-ui generated API docs from express, based on a swagger.json file. The result is a living documentation for your API hosted from your API server via a route.

  _Note - I have used the 2nd Method (using &#39;swagger-ui-express&#39;) to create the Swagger documentation._

  In the directory, the loginSwagger.yaml file contains all the definitions in YAML format. This is then converted into the swagger.json file. The &#39;swaggerDocs&#39; constant contains the reference to the JSON file that is used to setup the Swagger UI.

  The Swagger Document is now present on &#39;localhost:4000/swagger&#39;.


4. Once the REST API is defined by configuring the endpoint URLs with the appropriate HTTP/HTTPs security, input parameters and headers we can use the &quot;Try it out&quot; operation to test the API (similar to Postman). Here the parameter content type needs to be selected (it is &#39;application/json&#39; in my case). On filling the appropriate details of the POST Request in JSON we can run it by clicking on the execute button. Based on the content, if the POST request is valid we get a server response with the relevant details.

![Alt text](https://github.com/raunakmokhasi/LoginAuthenticationAPI/blob/master/Screens/SwaggerScreen2.JPG?raw=true "Swagger Request 1")

![Alt text](https://github.com/raunakmokhasi/LoginAuthenticationAPI/blob/master/Screens/SwaggerScreen3.JPG?raw=true "Swagger Request 2")


For further information regarding Swagger, please check out –

[https://swagger.io/docs/specification/2-0/basic-structure/](https://swagger.io/docs/specification/2-0/basic-structure/)



**Other Notes –**

_I have used Winston to create the Logger Template and Mockgoose in-order to mock the MongoDB operations during testing (using Mocha, Chai and Supertest)._

**--- Logic behind MOCKGOOSE/MONGO-MOCK/MongoDB-Memory-Server ---**

They are simplified in-memory databases that allow you to perform actions on Mongoose Models without having a running instance of MongoDB. By default, they are using in-memory store which does not have persistence, and a new mongod process takes about 7Mb of memory. If you invoke any save function, as long as you didn&#39;t start a new test run, data will be persisted, and you will be able to run &quot;find&quot; to get it back.

The primary purpose of them is to allow you to mock out your mongoose database during testing so that you do not have to create a new database for every test and then delete that same database afterwards. In these modules, the process of mocking works by recording database data used for a test by listening for all queries and responses during the initial testing stage. That information is stored (as mocking data) and is used in all future executions of the test in different environments. If over time, the tests navigation changes or queries are different, mocking data will need to be re-recorded. In case that during test execution, the tests need some data that was not recorded during the recording stage, that query will use real database data sources to get the answer.

In these modules, the in-memory database is a type of purpose-built database that relies primarily on memory for data storage, in contrast to databases that store data on disk or SSDs. In-memory databases are designed to attain minimal response time by eliminating the need to access disks. Because all data is stored and managed exclusively in main memory, it is at risk of being lost upon a process or server failure. In-memory databases can persist data on disks by storing each operation in a log or by taking snapshots. Thus, they are useful in mocking actual database operations without making a copy of the whole database.


**--- Why I have created a Logging Template ---**

This is mainly done in the 'loggerTemplate.js' file to ensure structured logging output. Sometimes, logs tend to be very subjective and up to the coder's views. Ensuring it is in a particular format through function parameters ensures that there are no discrepancies.

**References**

1. [https://expressjs.com/](https://expressjs.com/) / [https://www.npmjs.com/package/express](https://www.npmjs.com/package/express)
2. [https://express-validator.github.io/docs/](https://express-validator.github.io/docs/) / [https://www.npmjs.com/package/express-validator](https://www.npmjs.com/package/express-validator)
3. [https://www.npmjs.com/package/bcryptjs](https://www.npmjs.com/package/bcryptjs)
4. [https://www.npmjs.com/package/jsonwebtoken](https://www.npmjs.com/package/jsonwebtoken)
5. [https://www.npmjs.com/package/body-parser](https://www.npmjs.com/package/body-parser)
6. [https://www.npmjs.com/package/mongoose](https://www.npmjs.com/package/mongoose)
7. [https://www.npmjs.com/package/mockgoose](https://www.npmjs.com/package/mockgoose) / [https://github.com/mockgoose/Mockgoose](https://github.com/mockgoose/Mockgoose)
8. [https://mochajs.org/](https://mochajs.org/) / [https://www.npmjs.com/package/mocha](https://www.npmjs.com/package/mocha)
9. [https://www.chaijs.com/](https://www.chaijs.com/) / [https://www.npmjs.com/package/chai](https://www.npmjs.com/package/chai)
10. [https://github.com/winstonjs/winston /](https://github.com/winstonjs/winston%20/) / [https://www.npmjs.com/package/winston](https://www.npmjs.com/package/winston)
11. [https://www.npmjs.com/package/supertest](https://www.npmjs.com/package/supertest)
