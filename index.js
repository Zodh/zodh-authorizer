const CognitoClient = require('@aws-sdk/client-cognito-identity-provider');

const cognitoClient = new CognitoClient.CognitoIdentityProviderClient();

// TODO: refreshToken route.

exports.signUp = async (event) => {

  try {
    const signUpRequestBody = bodyParser(event.body);

    const signUpCommand = new CognitoClient.SignUpCommand({
      ClientId: process.env.COGNITO_CLIENT_ID,
      Username: signUpRequestBody.email,
      Password: signUpRequestBody.password,
      UserAttributes: [
        {
          Name: 'given_name', Value: signUpRequestBody.firstName
        },
        {
          Name: 'family_name', Value: signUpRequestBody.lastName
        },
      ]
    });

    const { UserSub } = await cognitoClient.send(signUpCommand);
    const user = {
      id: UserSub,
    };
    const signUpResponse = {
      message: 'User registered successfully!',
      user: user
    };

    return response(201, { signUpResponse });
  } catch(err) {
    if(err instanceof CognitoClient.UsernameExistsException) {
      return response(409, { message: 'This email is already in use!' });
    }
    return response(500, { message: 'Error trying to sign up user!', details: err.message });
  }
};

exports.confirm = async (event) => {
  try {
    const { email, code } = bodyParser(event.body);

    const accountConfirmationCommand = new CognitoClient.ConfirmSignUpCommand({
      ClientId: process.env.COGNITO_CLIENT_ID,
      Username: email,
      ConfirmationCode: code
    });

    await cognitoClient.send(accountConfirmationCommand);

    return response(204, { });
  } catch(err) {
    return response(500, { message: 'Error trying to confirm user account!', details: err.message });
  }
};

exports.signIn = async (event) => {
  try {
    const { email, password } = bodyParser(event.body);

    const initAuthCommand = new CognitoClient.InitiateAuthCommand({
      ClientId: process.env.COGNITO_CLIENT_ID,
      AuthFlow: 'USER_PASSWORD_AUTH',
      AuthParameters: {
        USERNAME: email,
        PASSWORD: password
      }
    });
    const { AuthenticationResult } = await cognitoClient.send(initAuthCommand);
    if(!AuthenticationResult) {
      return response(401, { message: 'Invalid credentials!' });
    }
    return response(200, {
      accessToken: AuthenticationResult.AccessToken,
      refreshToken: AuthenticationResult.RefreshToken,
    });
  } catch(err) {
    if (err instanceof CognitoClient.UserNotFoundException) {
      return response(401, { message: 'Invalid credentials!' });
    }
    if (err instanceof CognitoClient.UserNotConfirmedException) {
      return response(401, { message: 'Account not confirmed!' });
    }
    return response(500, { message: 'Error trying to sign in!', details: err.message });
  }
};

exports.getProfile = async (event) => {
  try {
    const userId = event.requestContext.authorizer.claims.username;
    const adminGetUserCommand = new CognitoClient.AdminGetUserCommand({
      Username: userId,
      UserPoolId: process.env.USER_POOL_ID,
    });
    const { UserAttributes } = await cognitoClient.send(adminGetUserCommand);
    const parsedProfile = UserAttributes?.reduce((profileData, { Name, Value }) => {
      const keyMap = {
        given_name: 'firstName',
        family_name: 'lastName',
        sub: 'id'
      };
      return {
        ...profileData,
        [keyMap[Name] ?? Name]: Value
      };
    }, {});
    return response(200, { profile: parsedProfile});
  } catch (err) {
    if(err instanceof CognitoClient.AdminGetUserCommand.UserNotFoundException) {
      return response(404, { message: 'User not found!' });
    }
    return response(500, { message: 'Error trying to fetch user data!', details: err.message });
  }
};

function response(statusCode, body) {
  return {
    statusCode,
    body: JSON.stringify(body),
  };
}

function bodyParser(body) {
  try {
    if (!body) {
      return {};
    }
    return JSON.parse(body);
  } catch {
    return {};
  }
}
