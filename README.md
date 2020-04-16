# custom-jwt-handler
## Use case
Through an external IdP JWT tokens are generated with "scope" defined in the payload. By providing this JWT token an access token can be
generated in APIM(wso2am-2.6.0). By default wso2am-2.6.0 will not append the scopes sent in JWT payload. Therefore, by implementing
a custom JWTGrantHandler we retrieve the scope from JWT payload and append it to the access token.

## Sample flow

1. Generate JWT in the IdP
   wso2is-5.7.0 has been used as the IDP here. Grant type is password and scope has been set as scope=app_eid
 - curl -k -d "grant_type=password&username=admin&password=admin&scope=app_eid" -u <client_id:client_secret> https://localhost:9443/oauth2/token

2. Get the JWT in the response
 - {
     "access_token":"value",
     "refresh_token":"refresh-token",
     "scope":"app_eid",
     "token_type":"Bearer",
     "expires_in":3600
  }
  
 3. Pass the JWT value and generate the access token APIM side
 - curl -i -X POST -H 'Content-Type: application/x-www-form-urlencoded' -u <app_client_id:app_client_secret> -k -d 'grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=value' https://localhost:8244/token
 
 4. The access token will be generated with as follows with the scope
 - {
     "access_token":"access-token",
     "refresh_token":"refresh-token",
     "scope":"app_eid",
     "token_type":"Bearer",
     "expires_in":3600
  }
