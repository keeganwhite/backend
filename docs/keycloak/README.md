# Keycloak Integration with iNethi Backend

## Set Up

To get auth working for the UI and App you need to set up your keycloak instance. Navigate to your keycloak URL. If you use the dev compose file then navigate to [http://localhost:8080/](http://localhost:8080/).

### Configuration

These steps will use the following env variables. Repalce them with your own where neccessary:

```
KEYCLOAK_MASTER_ADMIN="devuser"
KEYCLOAK_MASTER_ADMIN_PASSWORD="devpass"
KEYCLOAK_ADMIN="inethi"
KEYCLOAK_ADMIN_PASSWORD="iNethi2023#"
KEYCLOAK_URL="http://192.168.0.1:8080"
KEYCLOAK_REALM="inethi-services"
KEYCLOAK_BACKEND_CLIENT_ID="inethi-backend-client"
KEYCLOAK_CLIENT_SECRET="oq3BKpcKtiVyNXatzaelqW2QV2zji7YG"
```

These will be used in the [settings.py file](../../inethi/inethi/settings.py) to generate the `KEYCLOAK_OPENID`:

```
KEYCLOAK_OPENID = KeycloakOpenID(
    server_url=env("KEYCLOAK_URL"),
    client_id=env("KEYCLOAK_BACKEND_CLIENT_ID"),
    realm_name=env("KEYCLOAK_REALM"),
    client_secret_key=env("KEYCLOAK_CLIENT_SECRET"),
)
```

1. Create a new realm called `inethi-services`.

2. Ensure you are in this realm and then create a user with the username of `inethi` and password of `iNethi2023#`. Ensure email verification is set to on.

3. Navigate to `Role mapping` and assign the inethi user these roles:

- `realm-management` create-client
- `realm-management` manage-clients
- `realm-management` view-clients
- `realm-management` manage-users

4. Navigate to clients and create a client with the following details:

- Type: `OpenID Connect`
- Client ID: `inethi-backend-client`
- Name: `inethi-backend-client`
- Client authentication: `on`
- Authorization: `on`
- AUthentication flow: `standard flow, direct access grants, service account roles`
- Home URL: (enter your backend's URL): `http://localhost:8000`
- Valid redirect URIs: `http://localhost:8000/*`
- Valid post logout redirect URIs: `+`
- Web origins: `+`

5. Navigate to Credentials on the client and copy the `Client Secret` into your `.env` file and replace the default value for `KEYCLOAK_CLIENT_SECRET`. Then restart your backend docker containers:

```
docker compose -f docker-compose-dev.yml down
docker compose -f docker-compose-dev.yml build
docker compose -f docker-compose-dev.yml up -d
```
