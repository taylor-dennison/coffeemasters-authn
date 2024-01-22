# Coffee Masters Authentication Demo

This is the initial project for the FullStack Authentication workshop at Frontend Masters

Notes and recommendation:

- Keep the user's destination after login.  If a user tries to access an authenticated 
page while they are not authenticated, store the URL and redirect the user after the authentication process completes.

- Always confirm users emails.  We dont want anyone to just be able to create an account.  We want to ensure that
the user actually has access to that email by sending a verification. 

- Control login with a feature flag.  Some users do not want to just automatically be logged in, so offer a check box or some other
method of determining whether or not the user wants to opt into automatic login. 

- Check Privacy's legislation.  Ensure you abide by lawful guidelines regarding user data.

- Security is too important.  Do not deploy things until you are entirely sure that the authentication process is secure and flows properly.

- Test your login UX flows. 

Project TODOS:

1. Add validations
2. Add proper error management for every situation
3. Add Better database integrity
4. Add a "Forget Password" Flow
5. Confirm email on registration
6. Add "Sign in with Apple"
7. Add an OAuth 2.0 flow with Facebook or Github login
8. Add a Magic Link login
9. Implement Passkeys conditional UI (See https://simplewebauthn.dev/docs/packages/browser#browser-autofill-aka-conditional-ui)
10. Add a MFA manager, so users can delete and name saved authenticators
11. Add 2FA Authenticator App support