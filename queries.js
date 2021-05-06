const { Pool } = require("pg");
const connections = require("./connections");
const express = require("express");
const jwt = require("jsonwebtoken");
const bodyParser = require("body-parser");
const app = express();

const pool = new Pool(connections);
const port = process.env.PORT || 3000;

app.use(bodyParser.json());
app.use(
  bodyParser.urlencoded({
    extended: true,
  })
);
//Home Page
app.get("/", (request, response) => {
  response.json({
    Info: "Welcome to RESTFUL API for the Audit Table...",
  });
});
//GET all users: must create a valid Token to access this route
app.get("/audit_reports", verifyToken, (request, response) => {
  jwt.verify(request.token, "secretkey", (err, authData) => {
    if (err) {
      response.sendStatus(403);
    } else {
      pool.query(
        "SELECT * FROM audit_reports ORDER BY id ASC",
        (error, results) => {
          if (error) {
            throw error;
          }
          response.status(200).json(results.rows);
        }
      );
    }
    console.log(authData);
  });
});
//GET a single user by KEY only
app.get("/audit_reports/:key", verifyToken, (request, response) => {
  const key = parseInt(request.params.key);
  jwt.verify(request.token, "secretkey", (err, authData) => {
    if (err) {
      response.sendStatus(403);
    } else {
      pool.query(
        "SELECT * FROM audit_reports WHERE key = $1",
        [key],
        (error, results) => {
          if (error) {
            throw error;
          }
          response.status(200).json(results.rows);
        }
      );
    }
    console.log(authData);
  });
});
//POST a new user: Insert the new User
app.post("/audit_reports", (request, response) => {
  const {
    group_name,
    action_name,
    key,
    audit_data,
    status,
    comment,
    create_name,
  } = request.body;
  pool.query(
    "INSERT INTO audit_reports (group_name,action_name,key,audit_data,status,comment, create_name) VALUES ($1, $2, $3, $4, $5, $6, $7)",
    [group_name, action_name, key, audit_data, status, comment, create_name],
    (error, results) => {
      if (error) {
        throw error;
      }
      response
        .status(200)
        .send(`New User added to the audit_reports table: ${results.insertId}`);
    }
  );
});
//Delete User By ID
app.delete("/audit_reports/:id", (request, response) => {
  const id = parseInt(request.params.id);
  pool.query(
    "DELETE FROM audit_reports WHERE id = $1",
    [id],
    (error, results) => {
      if (error) {
        throw error;
      }
      response.status(200).send(`User deleted with ID: ${id}`);
    }
  );
});
//Create a valid Token
app.post("/createdToken", (request, response) => {
  const test = {
    UUUID: "Secrete",
    Author: "Sonny Nguyen",
    Email: "son.nguyen@dmv.ca.gov",
  };
  jwt.sign({ test }, "secretkey", { expiresIn: "100 days" }, (err, token) => {
    response.json({
      token,
    });
  });
});

//Middleware Function:
function verifyToken(request, response, next) {
  //Get header value:
  const bearerHeader = request.headers["authorization"];
  //Check if bearer is undefined:
  if (typeof bearerHeader !== "undefined") {
    //Split at the space:
    const bearer = bearerHeader.split(" ");
    //Get Token from the array:
    const bearerToken = bearer[1];
    //Set the Token
    request.token = bearerToken;
    //Call next Middleware:
    next();
  } else {
    //Forbidden
    response.sendStatus(403);
  }
}

app.listen(port, () => {
  console.log(`Server started running on port ${port}...`);
});

/*  Testing Area:
Delete: Test Data id
curl -X "DELETE" http://localhost:3000/audit_reports/9
Insert: a new user
curl --data "group_name=Tester10&action_name=Just_Request&key=785432&audit_data={'email':'example@gmail.com'}&status=Under_review&comment=no&create_name=Bill" 
http://localhost:3000/audit_reports
*/
