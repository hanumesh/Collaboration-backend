const request = require('supertest');
const app = require('./index');
const { header } = require('express-validator');
const expect = require('chai').expect;
const assert = require('chai').assert;

describe('Server Test', function() {
    it('API should return the correct version number', function(done) {
      request(app)
        .get('/')
        .end(function(err, response) {
          expect(response.body.version).to.be.ok;
          expect(response.statusCode).to.equal(200);
          expect(response.body.message).to.deep.equal("The API has started working!");
          done();
        });
    });
  });

describe('Signup Function Test', function() {   
    it('The test should PASS if the SIGNUP Credentials are valid but USER ALREADY EXISTS', function(done) {
        request(app)
           .post('/signup')
           .set('Accept', 'application/json')
           .set('Content-Type', 'application/json')
           //.send({ username: 'test', email: 'test@test.com', password: 'test123' })
           .send({ firstname: 'test', lastname: 'test' , email: 'test@test.com', password: 'test123' })
           .expect(400)   //Test for Bad Response 400 - User already exists
           .expect('Content-Type', /json/)
           .expect(function(response) {
                expect(response.body).not.to.be.empty; 
                expect(response.body).to.be.an('object');
                expect(response.body).to.have.property('message');
                expect(response.body.message).to.deep.equal("User Already Exists");
            })
           .end(done);
    }); 

    it('The test should PASS if the SIGNUP Credentials are invalid due to email', function(done) {
        request(app)
           .post('/signup')
           .set('Accept', 'application/json')
           .set('Content-Type', 'application/json')
           //.send({ username: 'arsenal', email: 'manu', password: 'chelsea123' })
           .send({ firstname: 'test', lastname: 'test' , email: 'test@test.com', password: 'test123' })
           .expect(300)   //Test for Error: Multiple Choices 300 - Invalid Email
           .expect('Content-Type', /json/)
           .expect(function(err, response) {
                expect(err).not.to.be.empty;
                expect(err.text).to.deep.equal('{"errors":[{"value":"manu","msg":"Please enter a valid Email","param":"email","location":"body"}]}');            
            })
           .end(done);
    });

    it('The test should PASS if the SIGNUP Credentials are invalid due to password length less than 5', function(done) {
        request(app)
           .post('/signup')
           .set('Accept', 'application/json')
           .set('Content-Type', 'application/json')
          // .send({ username: 'galaxy', email: 'hel@lo.com', password: 'hel' })
          .send({ firstname: 'test', lastname: 'test' , email: 'test@test.com', password: 'test123' })
           .expect(300)   //Test for Error: Multiple Choices 300 - Invalid Password (less than length 5)
           .expect('Content-Type', /json/)
           .expect(function(err, response) {
                expect(err).not.to.be.empty; 
                expect(err.text).to.deep.equal('{"errors":[{"value":"hel","msg":"Please enter a valid Password (of atleast 5 characters long)","param":"password","location":"body"}]}');
            })
           .end(done);
    });

});

describe('Login Function Test', function() {
    it('The test should PASS if the Login credentials are valid', function(done) {
        request(app)
           .post('/login')
           .set('Accept', 'application/json')
           .set('Content-Type', 'application/json')
           .send({ email: 'test@test.com', password: 'test123' })
           .expect(200)   //Test for Response OK Code - 200
           .expect('Content-Type', /json/) //Test for Content Type - application/json
           .expect(function(response) {    //Tests to check Response Body
              expect(response.body).not.to.be.empty; 
              expect(response.body).to.be.an('object');
              expect(response.body).to.have.property('token');
           })
           .end(done);
    }); 

    it('The test should PASS if the Login credentials are invalid and the User does not exist', function(done) {
        request(app)
           .post('/login')
           .set('Accept', 'application/json')
           .set('Content-Type', 'application/json')
           .send({ email: 'test98765@test.com', password: 'test12399' })
           .expect(409)  //Test for Response 409 Bad Request - User does not exist
           .expect('Content-Type', /json/)
           .expect(function(response) {
                expect(response.body).not.to.be.empty; 
                expect(response.body).to.be.an('object');
                expect(response.body).to.have.property('message');
                expect(response.body.message).to.deep.equal("User does NOT Exist");
            })
           .end(done);
    }); 

    it('The test should PASS if the Login credentials are invalid (Password is incorrect)', function(done) {
        request(app)
           .post('/login')
           .set('Accept', 'application/json')
           .set('Content-Type', 'application/json')
           .send({ email: 'test@test.com', password: 'test2499' })
           .expect(401)  //Test for Response 401 Authentication Error - Incorrect Password Entered
           .expect('Content-Type', /json/)
           .expect(function(response) {
                expect(response.body).not.to.be.empty; 
                expect(response.body).to.be.an('object');
                expect(response.body).to.have.property('message');
                expect(response.body.message).to.deep.equal("Incorrect Password Entered!");
            })
           .end(done);
    }); 

});


describe('Get User Info Test', function() {
    it('The test should PASS if the User Info is retrieved successfully and the Token is valid ', function(done) {
        request(app)
            .get('/getUserInfo')    
            .set('Accept', 'application/json')
            .set('Content-Type', 'application/json')
            .set('token', 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjp7ImlkIjoiNWVmMzAzMGU0ODI4NWEzOGUwZTkyZDhhIn0sImlhdCI6MTU5NDY0MjkwMiwiZXhwIjoxNTk3MjM0OTAyfQ.5ItDe9YjhtUs314NE98__qRjsiFxKsmxWbqCx7C5fqA')
            .expect(200)   //Test for Response OK Code - 200
            .expect('Content-Type', /json/) //Test for Content Type - application/json
            .expect(function(response) {    //Tests to check Response Body
              expect(response.body).not.to.be.empty; 
              expect(response.body).to.be.an('object');
              expect(response.body).to.have.property('email');
              expect(response.body.email).to.deep.equal('test@test.com');
              expect(response.body).to.have.property('username');
              expect(response.body.username).to.deep.equal('test');
              expect(response.body).to.have.property('password');
           })
           .end(done);
    }); 

    it('The test should PASS if the User Info is invalid and returns an invalid token error', function(done) {
        request(app)
            .get('/getUserInfo')    
            .set('Accept', 'application/json')
            .set('Content-Type', 'application/json')
            .set('token', 'bGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjp7ImlkIjoiNWVmMzAzMGU0ODI4NWEzOGUwZTkyZDhhIn0sImlhdCI6MTU5NDE5ODcwMiwiZXhwIjoxNTk2NzkwNzAyfQ.h6fzdTzyNS3NsPhAJGSsVs0UwOnFmueoIRcLs0LWF8Y')
            .expect(500)  //Test for INVALID TOKEN (Server Error)
            .end(done);
    });

});
