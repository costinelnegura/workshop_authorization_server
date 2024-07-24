# Workshop Authorization Server

This document provides instructions on how to test the Spring Security OAuth2 authorization server implementation using Postman.

## Testing the Implementation

To ensure that your authorization server is functioning correctly, you can use Postman to test the OAuth2 flow. Follow the steps below to test your setup:

### 1. Create a New Collection

- In Postman, create a new collection specifically for your OAuth2 tests.

### 2. Obtain an Access Token

To obtain an access token, perform the following steps:

#### 2.1 Create a New Request

- Create a new request within the collection you just created.

#### 2.2 Set Request Method

- Set the method of the request to `POST`.

#### 2.3 Configure Request URL

- Set the URL to your authorization server's token endpoint.  
  Example: `http://localhost:9000/oauth2/token`

#### 2.4 Authorization Setup

- Navigate to the "Authorization" tab.
- Select "OAuth 2.0" as the type.
- Click on "Get New Access Token".

#### 2.5 Fill in the OAuth2 Details

Fill in the following details in the dialog:

1. **Grant Type:** Authorization Code
2. **Callback URL:** The redirect URI configured for your client.  
   Example: `http://127.0.0.1:8080/login/oauth2/code/oidc-client`
3. **Auth URL:** The authorization endpoint URL.  
   Example: `http://localhost:9000/oauth2/authorize`
4. **Access Token URL:** The token endpoint URL.  
   Example: `http://localhost:9000/oauth2/token`
5. **Client ID and Client Secret:** Use the credentials configured in your `RegisteredClientRepository` bean.  
   In this example, use “oidc-client” and “secret”.
6. **Scope:** Specify the scope(s) you are requesting.  
   Example: “openid” or “profile”
7. **State:** A random string to protect against CSRF attacks.
8. **Client Authentication:** Send as Basic Auth header.

#### 2.6 Request Token

- Click "Request Token". You might be prompted to log in or consent to the scopes.

#### 2.7 Access Token

- After successful authentication and authorization, you'll receive an access token.

Follow these steps to test different aspects of your OAuth2 authorization server and ensure it is configured correctly.
