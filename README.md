# iNethi Backend
The backend for the bespoke iNethi system.

## Commands
### Running the Code

**Dev**

To run the code run `docker compose -f docker-compose-dev.yml up`

**Prod**

_to do_

### Testing
Ensure the `DEV` variable in the [compose file](docker-compose.yml) is set to true: `DEV=true`.

* run flake8 in your docker container: `docker compose run --rm app sh -c "flake8"`
* run unit tests in your docker container: `docker compose run --rm app sh -c "python manage.py test"`

## Notes
* if you want to run Django locally without docker, and you want to use _psycopg2_ you can either run 
`pip install psycopg2-binary` (not compiled for your OS so it is **not recommended for deployment**) else install the
build dependencies for _psycopg2_. You can find them [here](https://www.psycopg.org/docs/install.html) or for Ubuntu run
```
sudo apt-get install python3-dev
sudo apt install gcc
sudo apt install build-essential
sudo apt install libpq-dev
```
then run `pip install psycopg2` to install _psycopg2_.