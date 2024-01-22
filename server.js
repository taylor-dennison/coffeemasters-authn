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

app.post('/auth/auth-options', (req, res) => {
  const foundUser = findUser(req.body.email);
  if (foundUser) {
    //send what auth options are available for user to client.
    res.send({
      password: foundUser.password != false,
      google: foundUser.federated && foundUser.federated.google,
      webauthn: foundUser.webauthn,
    });
  } else {
    //in effort to give attackers less information, dont tell the client anything is wrong, just send password: true
    //to show the password field.
    res.send({ password: true });
  }
});

//WEBAUTHN ENDPOINTS
// FIRST TWO ENDPOINTS ARE REGISTRATION FOCUSED. THE LAST TWO ARE LOGIN FOCUSED
app.post("/auth/webauth-registration-options", (req, res) =>{
  const user = findUser(req.body.email);

  //this object is passed to the authenticator. 
  //rp is the relying party. This is our server.
  const options = {
      rpName: 'Coffee Masters',
      rpID,  //this is defined as a constant above.  This is typically the domain name of the server
      userID: user.email,
      userName: user.name,
      timeout: 60000, //how much time will we wait for the user to complete the process.
      attestationType: 'none',
      
      /**
       * Passing in a user's list of already-registered authenticator IDs here prevents users from
       * registering the same device multiple times. The authenticator will simply throw an error in
       * the browser if it's asked to perform registration when one of these ID's already resides
       * on it.
       */
      //excludeCredentials ensures that the authenticator does not already have a credential registered to it. 
      //This is important because we don't want to register the same device (or same face id, eg.) multiple times.
      excludeCredentials: user.devices ? user.devices.map(dev => ({
          id: dev.credentialID,
          type: 'public-key',
          transports: dev.transports,
      })) : [],

      //optional, but recommended. 
      authenticatorSelection: {
          userVerification: 'required', 
          residentKey: 'required',
      },
      /**
       * The two most common algorithms: ES256, and RS256
       */
      supportedAlgorithmIDs: [-7, -257],
  };

  /**
   * The server needs to temporarily remember this value for verification, so don't lose it until
   * after you verify an authenticator response.
   */
  // This comes form the SimpleWebAuthnServer library.
  const regOptions = SimpleWebAuthnServer.generateRegistrationOptions(options)
  //we need to store the challenge in the user object so we can verify it later.
  user.currentChallenge = regOptions.challenge;
  db.write();
  
  res.send(regOptions);
});

app.post("/auth/webauth-registration-verification", async (req, res) => {
  const user = findUser(req.body.user.email);
  const data = req.body.data;

  const expectedChallenge = user.currentChallenge;

  let verification;
  try {
    const options = {
      credential: data,
      expectedChallenge: `${expectedChallenge}`,
      expectedOrigin,
      expectedRPID: rpID,
      requireUserVerification: true,
    };
    verification = await SimpleWebAuthnServer.verifyRegistrationResponse(options);
  } catch (error) {
  console.log(error);
    return res.status(400).send({ error: error.toString() });
  }

  const { verified, registrationInfo } = verification;

  if (verified && registrationInfo) {
    const { credentialPublicKey, credentialID, counter } = registrationInfo;

    const existingDevice = user.devices ? user.devices.find(
      device => new Buffer(device.credentialID.data).equals(credentialID)
    ) : false;
    //if the device is not already registered, add it to the user's devices.
    if (!existingDevice) {
      const newDevice = {
        credentialPublicKey,
        credentialID,
        counter,
        transports: data.response.transports,
      };
      //if the user does not have a devices array, create one.
      if (user.devices==undefined) {
          user.devices = [];
      }
      user.webauthn = true;
      user.devices.push(newDevice);
      db.write();
    }
  }

  res.send({ ok: true });

});

app.post("/auth/webauth-login-options", (req, res) =>{
  const user = findUser(req.body.email);
  // if (user==null) {
  //     res.sendStatus(404);
  //     return;
  // }
  const options = {
      timeout: 60000,
      allowCredentials: [],
      devices: user && user.devices ? user.devices.map(dev => ({
        id: dev.credentialID,
        type: 'public-key',
        transports: dev.transports,
      })) : [],
      userVerification: 'required',
      rpID,
  };
  const loginOpts = SimpleWebAuthnServer.generateAuthenticationOptions(options);
  if (user) user.currentChallenge = loginOpts.challenge;
  res.send(loginOpts);
});

app.post("/auth/webauth-login-verification", async (req, res) => {
  const data = req.body.data;
  const user = findUser(req.body.email);
  if (user==null) {
      res.sendStatus(400).send({ok: false});
      return;
  } 

  const expectedChallenge = user.currentChallenge;

  let dbAuthenticator;
  const bodyCredIDBuffer = base64url.toBuffer(data.rawId);

  for (const dev of user.devices) {
    const currentCredential = Buffer(dev.credentialID.data);
    if (bodyCredIDBuffer.equals(currentCredential)) {
      dbAuthenticator = dev;
      break;
    }
  }

  if (!dbAuthenticator) {
    return res.status(400).send({ ok: false, message: 'Authenticator is not registered with this site' });
  }

  let verification;
  try {
    const options  = {
      credential: data,
      expectedChallenge: `${expectedChallenge}`,
      expectedOrigin,
      expectedRPID: rpID,
      authenticator: {
          ...dbAuthenticator,
          credentialPublicKey: new Buffer(dbAuthenticator.credentialPublicKey.data) // Re-convert to Buffer from JSON
      },
      requireUserVerification: true,
    };
    verification = await SimpleWebAuthnServer.verifyAuthenticationResponse(options);
  } catch (error) {
    return res.status(400).send({ ok: false, message: error.toString() });
  }

  const { verified, authenticationInfo } = verification;

  if (verified) {
    dbAuthenticator.counter = authenticationInfo.newCounter;
  }

  res.send({ 
      ok: true, 
      user: {
          name: user.name, 
          email: user.email
      }
  });
});

app.post('/auth/login', (req, res) => {
  const userFound = findUser(req.body.email);
  if (!userFound) {
    res.status(401).send({ ok: false, message: 'Credentials are wrong' });
    return;
  }
  //we have found the user. Check the password
  const passwordMatch = bcrypt.compareSync(
    req.body.password,
    userFound.password,
  );
  if (!passwordMatch) {
    res.status(401).send({ ok: false, message: 'Credentials are wrong' });
    return;
  }

  //we have a valid user and password.
  return res
    .status(200)
    .send({ ok: true, name: userFound.name, email: userFound.email });
});

app.post('/auth/login-google', (req, res) => {
  let jwt = jwtJsDecode.jwtDecode(req.body.credential.credential);
  let user = {
    name: jwt.payload.name,
    email: jwt.payload.email,
    password: false,
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
    res.send({ ok: true, name: userFound.name, email: userFound.email });
  } else {
    db.data.users.push({
      ...user,
      federated: {
        google: jwt.payload.aud,
      },
    });
    db.write();
    res.send({ ok: true, name: userFound.name, email: userFound.email });
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
    res.status(400).send({ ok: false, message: 'User already exists' });
    return;
  } else {
    //user is new.
    db.data.users.push(user);
    db.write();
    res.status(201).send({ ok: true, message: 'User registered' });
  }
});

app.get('*', (req, res) => {
  res.sendFile(__dirname + 'public/index.html');
});

app.listen(port, () => {
  console.log(`App listening on port ${port}`);
});
