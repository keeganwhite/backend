# Setting Up The System

1. Populate a `.env` file.
2. If you don't have keycloak and radiusdesk you need to set these up. The details for Keycloak can be found [here](./keycloak/README.md).
3. Run the compose file of your choosing then run `docker exec inethi-backend python manage.py create_superuser`.
4. Create json files and place them in the [inethi dir](../inethi/) for your NETWORK admin user(s), RADIUSDesk instance(s) and smart contract(s) commands, see the [users example](./examples/users.json), [RADIUSDesk example](./examples/sample_radiusdesk_config.json) and the contracts [example](./examples/smart_contracts.json) then run the following:

```
docker exec -it inethi-backend sh
python manage.py create_users_from_json user.json
python manage.py create_smart_contracts_from_json smart_contracts.json
python manage.py create_radiusdesk_from_json sample_radiusdesk_config.json
```
