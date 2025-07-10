import requests
import time

HEADERS = {
    "Content-Type":
        "application/json"
}
HEADERS_URL_ENCODED = {
    "Content-Type":
        "application/x-www-form-urlencoded; charset=UTF-8"
}


def login(username, password, base_url):
    """Authenticate and retrieve the token."""
    login_url = f"{base_url}/dashboard/authenticate.json"
    print(f"Logging in to {login_url}")
    payload = {
        "auto_compact": "false",
        "username": username,
        "password": password,
    }

    response = requests.post(
        login_url,
        headers=HEADERS_URL_ENCODED,
        data=payload
    )

    if response.status_code == 200 and response.json().get("success"):
        return response.json()["data"]["token"]
    else:
        raise Exception("Login failed")


def check_token(token, base_url):
    """Check the validity of the token."""

    check_token_url = f"{base_url}/dashboard/check_token.json"

    params = {
        "_dc": "1737643751868",  # Simulating a random timestamp
        "token": token,
        "auto_compact": "false",
    }
    cookies = {"Token": token}
    response = requests.get(
        check_token_url,
        headers=HEADERS_URL_ENCODED,
        params=params,
        cookies=cookies
    )
    if response.status_code == 200:
        return True
    else:
        return False


def fetch_vouchers(token, cloud_id, base_url, limit=100):
    """Fetch vouchers from the RADIUSdesk API."""
    url = f"{base_url}/vouchers/index.json"  # Correctly formatted URL

    params = {
        "_dc": "1737644419602",
        "page": 1,
        "start": 0,
        "limit": limit,
        "token": token,
        "sel_language": "4_4",
        "cloud_id": cloud_id,
    }
    cookies = {"Token": token}

    print(f"Fetching vouchers from {url}")
    print(f"Params being sent: {params}")

    response = requests.get(
        url,
        headers=HEADERS_URL_ENCODED,
        params=params,
        cookies=cookies
    )

    print(f"Final URL being requested: {response.url}")  # Debug output

    if response.status_code == 200:
        return response.json()
    else:
        raise Exception(f"Failed to fetch vouchers: {response.text}")


def fetch_voucher_details(token, voucher_code, cloud_id, base_url, limit=150):
    """
    Fetch the details of a specific voucher from the RADIUSdesk API.

    The voucher is identified by its voucher_code which is sent as the
    'username' parameter.
    """
    url = f"{base_url}/radaccts/index.json"

    # Generate a current timestamp string for the _dc parameter
    timestamp = str(int(time.time() * 1000))

    params = {
        "_dc": timestamp,
        "username": voucher_code,  # voucher_code is passed as the username.
        "page": 1,
        "start": 0,
        "limit": limit,
        "token": token,
        "sel_language": "4_4",
        "cloud_id": cloud_id,
    }
    cookies = {"Token": token}

    print(f"Fetching voucher details from {url}")
    print(f"Params being sent: {params}")

    response = requests.get(
        url,
        headers=HEADERS_URL_ENCODED,
        params=params,
        cookies=cookies
    )

    print(f"Final URL being requested: {response.url}")

    if response.status_code == 200:
        return response.json()
    else:
        raise Exception(f"Failed to fetch voucher details: {response.text}")


def create_voucher(
        token,
        base_url,
        cloud_id,
        realm_id,
        profile_id,
        quantity=1
):
    url = f"{base_url}/vouchers/add.json"

    """Create voucher in the RADIUSdesk API."""
    payload = {
        "single_field": "true",
        "realm_id": realm_id,
        "profile_id": profile_id,
        "quantity": quantity,
        "never_expire": "on",
        "extra_name": "",
        "extra_value": "",
        "token": token,
        "sel_language": "4_4",
        "cloud_id": cloud_id,
    }

    cookies = {"Token": token}
    response = requests.post(
        url,
        headers=HEADERS_URL_ENCODED,
        data=payload,
        cookies=cookies
    )
    if response.status_code == 200:
        if quantity == 1:
            voucher = response.json()["data"][0]['name']
            return voucher
        return response.json()

    else:
        raise Exception("Failed to add voucher")
