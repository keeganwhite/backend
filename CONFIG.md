# iNethi Backend Config
This file uses the defaults set in the [.env.example](.env.example) file.
## Keycloak
1. To use the keycloak system for authentication you need to create a keycloak realm named `inethi-services`.
2. Create a client called `inethi-backend-client`, ensure client authentication and authorization are checked. Set the  
home url to your backend's URL, your redirect URLs to your backend URL with a wild card suffix and set web origins and 
valid post logout redirects to `+`
3. Get your Keycloak client secret from the `credentials` tab and set this in your `.env` file.
4. Add a user to your realm with the username `inethi` and password `iNethi2023#`. Ensure you give the user an email,
first name, last name, tick the email verified box and add a password under the `credentials` tab.
5. Assign this user the `realm-admin` role under the `Role Mapping` tab.