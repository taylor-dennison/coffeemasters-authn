import express from 'express';
import { Low } from 'lowdb';
import { JSONFile } from 'lowdb/node';
import * as url from 'url';
import bcrypt from 'bcryptjs';
import * as jwtJsDecode from 'jwt-js-decode';
import base64url from 'base64url';
import SimpleWebAuthnServer from '@simplewebauthn/server';

const __dirname = url.fileURLToPath(new URL('.', import.meta.url));

const app = express();
app.use(express.json());

const adapter = new JSONFile(__dirname + '/auth.json');
const db = new Low(adapter);
await db.read();
db.data ||= { users: [] };

const rpID = 'localhost';
const protocol = 'http';
const port = 5050;
const expectedOrigin = `${protocol}://${rpID}:${port}`;

app.use(express.static('public'));
app.use(express.json());
app.use(
  express.urlencoded({
    extended: true,
  }),
);

// ADD HERE THE REST OF THE ENDPOINTS
const findUser = (email) => {
  const results = db.data.users.filter((u) => u.email === email);
  if (results.length === 0) {
    return undefined;
  }
  return results[0];
};

app.post('/auth/login', (req, res) => {
  const userFound = findUser(req.body.email);
  if (!userFound) {
    res.status(401).send({ok: false, message: 'Credentials are wrong'});
    return;
  }
  //we have found the user. Check the password
  const passwordMatch = bcrypt.compareSync(req.body.password, userFound.password);
  if (!passwordMatch) {
    res.status(401).send({ok: false, message: 'Credentials are wrong'});
    return;
  }

  //we have a valid user and password. 
  return res.status(200).send({ok: true, name: userFound.name, email: userFound.email});

})

app.post('/auth/login-google', (req, res) => {
  let jwt = jwtJsDecode.jwtDecode(req.body.credential.credential);
  let user = {
    name: jwt.payload.name,
    email: jwt.payload.email,
    password: null,
  };

  //check if user already exists
  const userFound = findUser(user.email);
  if (userFound) {
    // since we may have more than one federated login,
    // we should use a federated object to store the information in the db that 
    // could contain multiple federated logins.
    user.federated = { 
      google: jwt.payload.aud,
    }; //google id from jwt
    db.write();
    res.send({ok: true, name: userFound.name, email: userFound.email});
  } else {
    db.data.users.push({
      ...user,
      federated: {
        google: jwt.payload.aud,
      },
    });
    db.write();
    res.send({ok: true, name: userFound.name, email: userFound.email});
  }
});

app.post('/auth/register', (req, res) => {
  //TODO: DATA VALIDATION + SANITIZATION
  //Also, we confirm users email addresses by sending them an email with a link to confirm their email address

  const salt = bcrypt.genSaltSync(10); 
  //there is also an async version of this function
  const hashedPassword = bcrypt.hashSync(req.body.password, salt);

  const user = {
    name: req.body.name,
    email: req.body.email,
    password: hashedPassword,
  };
  //check if user already exists
  const userFound = findUser(user.email);

  if (userFound) {
    res.status(400).send({ok: false, message: 'User already exists'});
    return;
  } else {
    //user is new. 
    db.data.users.push(user);
    db.write();
    res.status(201).send({ok: true, message: 'User registered'});
  }
});

app.get('*', (req, res) => {
  res.sendFile(__dirname + 'public/index.html');
});

app.listen(port, () => {
  console.log(`App listening on port ${port}`);
});
