const express = require("express");
const app = express();
var cors = require('cors')
const bodyParser = require("body-parser");  //Used to parse incoming requests in a middleware before your handlers
const cookieParser=require('cookie-parser');
const InitiateMongoServer = require("./db");

const winstonLogger = require("./winstonLogger");

InitiateMongoServer();

const PORT = process.env.PORT || 5000;
const HOSTNAME = '0.0.0.0';

app.use(cors()) // Use this after the variable declaration
app.use(bodyParser.json());
app.use(cookieParser());

app.get("/", (req, res) => {
  res.json({ version: '1.0.0', message: "The Collaboration REST API is working!" });
  winstonLogger.log('info', `The Collaboration REST API is working!`);
});


app.listen(PORT, HOSTNAME, (req, res) => {
  //console.log(`The server has been initiated at PORT ${PORT}`);
  console.log();
  winstonLogger.log('info', `The server has been initiated at PORT: HOSTNAME ${PORT} ${HOSTNAME}`);
});

const jwt = require("jsonwebtoken"); //Secure way to transmit information between parties as a JSON object with a Digital Signature
const { check, validationResult } = require("express-validator"); // Prevents request that includes invalid username or password
const bcrypt = require("bcryptjs"); //Secure way to store passwords in Database using Encryption Techniques (Generating salt and hashing)
const User = require("./UserSchema");
const {auth} =require('./auth');

const swaggerJsDoc = require('swagger-jsdoc');
const swaggerUi = require('swagger-ui-express');
const swaggerDocs = require('./swagger.json');

app.use('/swagger', swaggerUi.serve, swaggerUi.setup(swaggerDocs));

app.post(
  "/api/signup",
  [
    check("firstname", "Please enter a valid firstname").not().isEmpty(),
    check("lastname", "Please enter a valid lastname").not().isEmpty(),
    check("email", "Please enter a valid Email").isEmail(),
    check("password", "Please enter a valid Password (of atleast 5 characters long)").isLength({ min: 5 })
  ],
  async (req, res) => {
    const errors = validationResult(req); //Extracts the validation errors from the Express request and makes them available in a Result object.
    if (!errors.isEmpty()) {
      return res.status(300).json({
        errors: errors.array()
      });
    }

    const { firstname, lastname, email, password } = req.body;
    //Here, as req.body's shape is based on user-controlled input, all properties and values in this object are untrusted and should be validated before trusting. Thus we use body-parser to parse incoming requests in the middleware before the handlers
    try {
      let user = await User.findOne({ email }); //MongoDB method to search the collection and find a record that matches the given parameter (in this case email)
      if (user) {
        return res.status(400).json({ message: "User Already Exists" });
      }

      user = new User({ firstname, lastname, email, password });

      const saltValue = await bcrypt.genSalt(10);
      user.password = await bcrypt.hash(password, saltValue);
      await user.save();

      const payload = {
        user: {
          id: user.id,
          firstname: user.firstname,
          lastname: user.lastname
        }
      };

      /// newuser.save((err,doc)=>{
      if (err) {
        console.log(err);
        return res.status(400).json({ success: false });
      }
      res.status(200).json({
        succes: true,
        user: payload
      });
      // });

      // jwt.sign(
      //   payload, "mysecretkey", { expiresIn: '30d' },
      //   //Token ID keeps changing as payload expires every month
      //   (err, token) => {
      //     if (err) throw err;
      //     res.status(200).json({ token });
      //   }
      // );
    }
    catch (err) {
      console.log(err.message);
      res.status(500).send("Error while Saving Data");
    }
  }
);


// adding new user (sign-up route)
app.post('/signup',function(req,res){
  // taking a user
  const newuser=new User(req.body);
  console.log(newuser);

  //if(newuser.password!=newuser.password2)return res.status(400).json({message: "password not match"});
  
  User.findOne({email:newuser.email},function(err,user){
      if(user) return res.status(400).json({ auth : false, message :"email exits"});

      newuser.save((err,doc)=>{
          if(err) {console.log(err);
              return res.status(400).json({ success : false});}
          res.status(200).json({
            
              succes:true,
              user : doc
          });
      });
  });
});


// login user
app.post('/api/login', function(req,res){
   let token=req.cookies.auth;
   User.findByToken(token,(err,user)=>{
       if(err) return  res(err);
       if(user) return res.status(400).json({
           error :true,
           message:"You are already logged in"
       });
   
       else{
           User.findOne({'email':req.body.email},function(err,user){
               if(!user) return res.json({isAuth : false, message : ' Auth failed ,email not found'});
       
               user.comparepassword(req.body.password,(err,isMatch)=>{
                   if(!isMatch) return res.json({ isAuth : false,message : "password doesn't match"});
       
               user.generateToken((err,user)=>{
                   if(err) return res.status(400).send(err);
                   res.cookie('auth',user.token).json({
                       isAuth : true,
                       id : user._id
                       ,email : user.email,
                       token : user.token
                   });
               });    
           });
         });
       }
   });
});


app.post('/login', function(req,res){
  let token=req.cookies.auth;
  User.findByToken(token,(err,user)=>{
      if(err) return  res(err);
      if(user) return res.status(400).json({
          error :true,
          message:"You are already logged in"
      });
  
      else{
          User.findOne({'email':req.body.email},function(err,user){
              if(!user) return res.json({isAuth : false, message : ' Auth failed ,email not found'});
      
              // user.comparepassword(req.body.password,(err,isMatch)=>{
              //     if(!isMatch) return res.json({ isAuth : false,message : "password doesn't match"});
      
              user.generateToken((err,user)=>{
                  if(err) return res.status(400).send(err);
                  res.cookie('auth',user.token).json({
                      isAuth : true,
                      id : user._id
                      ,email : user.email,
                      token:user.token
                  });
              });    
        //  });
        });
      }
  });
});

app.post(
  "api/login",
  [
    check("email", "Please enter a valid Email").isEmail(),
    check("password", "Please enter a valid Password").isLength({ min: 6 })
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        errors: errors.array()
      });
    }
    const { email, password } = req.body;

    try {
      let user = await User.findOne({ email });
      if (!user)
        return res.status(409).json({ message: "User does NOT Exist" });

      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch)
        return res.status(401).json({ message: "Incorrect Password Entered!" });

      const payload = {
        user: {
          id: user.id,
          firstname: user.firstname,
          lastname: user.lastname
        }
      };

      user.generateToken((err, user) => {
        if (err) return res.status(400).send(err);
        res.cookie('auth', user.token).json({
          isAuth: true,
          id: user._id,
          email: user.email
        });
        res.status(200).json({ user });
      });

      // jwt.sign(payload, "mysecretkey", { expiresIn: '30d' },
      //   (err, token) => {
      //     if (err) throw err;
      //     res.status(200).json({ token });
      //   }
      // );
    }
    catch (e) {
      //console.error(e);
      winstonLogger.log('error', new Error(e));
      res.status(500).json({ message: "Server Error" });
    }
  }
);

app.get('/logout',auth,function(req,res){
  req.user.deleteToken(req.token,(err,user)=>{
      if(err) return res.status(400).send(err);
      res.sendStatus(200);
  });

}); 

app.get('/profile',auth,function(req,res){
  res.json({
      isAuth: true,
      id: req.user._id,
      email: req.user.email,
      name: req.user.firstname + req.user.lastname
      
  })
});

app.get('/saveNewAutomationIdea',auth,function(req,res){
  res.json({
      isAuth: true,
      id: req.user._id,
      email: req.user.email,
      name: req.user.firstname + req.user.lastname
      
  })
});


module.exports = app;
