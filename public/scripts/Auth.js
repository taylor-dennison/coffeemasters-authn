import API from './API.js';
import Router from './Router.js';

const Auth = {
  isLoggedIn: false,
  account: null,
  loginStep: 1, //used to control the flow of authentication.
  postLogin: (response, user) => {
    if (response.ok) {
      Auth.isLoggedIn = true;
      Auth.account = user;
      Auth.updateStatus();
      Router.go('/account');
    } else {
      alert(response.message);
    }

    //Credential Management API Storage
    //this will store the credentials in the browser for auto login
    /* **NOTE: PasswordCredential API is not supported in Safari yet, as a whole.
              It will work with the WebAuthn API (AKA: Passkeys), but not the PasswordCredential API for username/passwords.
              This if block will determine whether or not we are on a chromium browser or not,
              since this will be falsy in Safari.
        */
    if (window.PasswordCredential && user.password) {
      const credentials = new PasswordCredential({
        id: user.email,
        name: user.name, //name is optional for PasswordCredential.
        password: user.password,
      });
      navigator.credentials.store(credentials);
    }
  },
  register: async (event) => {
    event.preventDefault();
    const user = {
      name: document.querySelector('#register_name').value,
      email: document.querySelector('#register_email').value,
      password: document.querySelector('#register_password').value,
    };
    const response = await API.register(user);
    if (response.ok) {
      Auth.postLogin(response, user);
    } else {
      alert(response.message);
    }
  },
  loginFromGoogle: async (data) => {
    const response = await API.loginFromGoogle({
      credential: data,
    });
    Auth.postLogin(response, {
      name: response.name,
      email: response.email,
    });
  },
  checkAuthOptions: async () => {
    const response = await API.checkAuthOptions({
      email: document.querySelector('#login_email').value,
    });
    Auth.loginStep = 2; //we are now on login step 2

    if (response.password) {
      document.querySelector('#login_section_password').hidden = false;
    }
    if (response.webauthn) {
      document.querySelector('#login_section_webauthn').hidden = false;
    }
  },
  addWebAuthn: async (event) => {
    //wait for server to send registration options
    const options = await API.webAuthn.registrationOptions();
    //add additional options client side.
    options.authenticatorSelection.residentKey = 'required';
    options.authenticatorSelection.requiresResidentKey = 'required';
    options.extensions = {
      credProps: true,
    };

    const authRes = await SimpleWebAuthnBrowser.startRegistration(options);
    //send the response to the server for verification
    const verificationResponse = await API.webAuthn.registrationVerification(authRes);
    if (verificationResponse.ok) {
        alert("You can now login using WebAuthn!");
    } else {
        alert(verificationResponse.message);
        }
  },
  webAuthnLogin: async (event) => {
    const email = document.querySelector('#login_email').value;
    const options = await API.webAuthn.loginOptions(email);
    const loginResponse = await SimpleWebAuthnBrowser.startAuthentication(options);
    const verificationResponse = await API.webAuthn.loginVerification(email, loginResponse);
    if (verificationResponse.ok) {
        Auth.postLogin(verificationResponse, verificationResponse.user);
    } else {
        alert(verificationResponse.message);
    }
  },
  login: async (event) => {
    if (event) event.preventDefault(); //autologin does not have an event
    if (Auth.loginStep === 1) {
      //check to see what sign in/authentication options are available
      Auth.checkAuthOptions();
    } else {
      //login step 2
      const user = {
        email: document.querySelector('#login_email').value,
        password: document.querySelector('#login_password').value,
      };
      //log in
      const response = await API.login(user);
      //using the response to grab the name, we can create the user object here.
      Auth.postLogin(response, {
        ...user,
        name: response.name,
      });
    }
  },
  logout: () => {
    Auth.isLoggedIn = false;
    Auth.account = null;
    Auth.updateStatus();
    Router.go('/');

    // instruct the PasswordCredential API to forget the credentials
    if (window.PasswordCredential) {
      navigator.credentials.preventSilentAccess();
    }
  },
  autoLogin: async () => {
    if (window.PasswordCredential) {
      const credentials = await navigator.credentials.get({ password: true });
      //depending on the use case, we can just call Auth.login(credentials) here,
      //or we can auto fill the login form and let the user click the login button.
      if (credentials) {
        try {
          document.querySelector('#login_email').value = credentials.id;
          document.querySelector('#login_password').value =
            credentials.password;
          //if we do call the login method, since we are not passing an event
          //here, we need to check if an event exists, as done above.
          Auth.login();
        } catch (error) {}
      }
    }
  },
  updateStatus() {
    if (Auth.isLoggedIn && Auth.account) {
      document
        .querySelectorAll('.logged_out')
        .forEach((e) => (e.style.display = 'none'));
      document
        .querySelectorAll('.logged_in')
        .forEach((e) => (e.style.display = 'block'));
      document
        .querySelectorAll('.account_name')
        .forEach((e) => (e.innerHTML = Auth.account.name));
      document
        .querySelectorAll('.account_username')
        .forEach((e) => (e.innerHTML = Auth.account.email));
    } else {
      document
        .querySelectorAll('.logged_out')
        .forEach((e) => (e.style.display = 'block'));
      document
        .querySelectorAll('.logged_in')
        .forEach((e) => (e.style.display = 'none'));
    }
  },
  init: () => {
    document.querySelectorAll('#login_section_password').hidden = true;
    document.querySelectorAll('#login_section_webauthn').hidden = true;
  },
};
Auth.updateStatus();
//attempt autologin if user has previously logged in and credentials
//are stored in the password manager
Auth.autoLogin();

export default Auth;

// make it a global object
window.Auth = Auth;
