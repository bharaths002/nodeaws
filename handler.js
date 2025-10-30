

import crypto from "crypto";
import {
  CognitoIdentityProviderClient,
  InitiateAuthCommand,
  ChangePasswordCommand,
} from "@aws-sdk/client-cognito-identity-provider";

const client = new CognitoIdentityProviderClient({ region: "ap-south-1" });

function generateSecretHash(username, clientId, clientSecret) {
  return crypto
    .createHmac("SHA256", clientSecret)
    .update(username + clientId)
    .digest("base64");
}

// ------------------------- LOGIN HANDLER -------------------------
export const login = async (event) => {
  try {
    const body = JSON.parse(event.body);
    const { email, password } = body;

    if (!email || !password) {
      return {
        statusCode: 400,
        body: JSON.stringify({
          message: "Email and password are required",
        }),
      };
    }

    const CLIENT_ID = process.env.CLIENT_ID;
    const CLIENT_SECRET = process.env.CLIENT_SECRET;

    const secretHash = generateSecretHash(email, CLIENT_ID, CLIENT_SECRET);

    const params = {
      AuthFlow: "USER_PASSWORD_AUTH",
      ClientId: CLIENT_ID,
      AuthParameters: {
        USERNAME: email,
        PASSWORD: password,
        SECRET_HASH: secretHash,
      },
    };

    const command = new InitiateAuthCommand(params);
    const response = await client.send(command);

    return {
      statusCode: 200,
      body: JSON.stringify({
        message: "Login successful",
        tokens: response.AuthenticationResult,
      }),
    };
  } catch (err) {
    console.error("Login error:", err);
    return {
      statusCode: 400,
      body: JSON.stringify({
        message: "Login failed",
        error: err.message,
      }),
    };
  }
};

// --------------------- CHANGE PASSWORD HANDLER ---------------------
export const changePassword = async (event) => {
  try {
    const body = JSON.parse(event.body);
    const { oldPassword, newPassword } = body;

    if (!oldPassword || !newPassword) {
      return {
        statusCode: 400,
        body: JSON.stringify({
          message: "Old and new password are required",
        }),
      };
    }


    const authHeader = event.headers.Authorization || event.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return {
        statusCode: 401,
        body: JSON.stringify({ message: "Missing or invalid Authorization header" }),
      };
    }

    const accessToken = authHeader.replace("Bearer ", "").trim();

    const params = {
      PreviousPassword: oldPassword,
      ProposedPassword: newPassword,
      AccessToken: accessToken,
    };

    const command = new ChangePasswordCommand(params);
    await client.send(command);

    return {
      statusCode: 200,
      body: JSON.stringify({
        message: "Password changed successfully",
      }),
    };
  } catch (err) {
    console.error("Change Password error:", err);
    return {
      statusCode: 400,
      body: JSON.stringify({
        message: "Password change failed",
        error: err.message,
      }),
    };
  }
};
