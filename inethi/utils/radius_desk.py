import requests

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


def fetch_vouchers(token, cloud_id, base_url):
    """Fetch vouchers from the RADIUSdesk API."""
    url = f"{base_url}/cake4/rd_cake/vouchers/index.json"
    params = {
        "_dc": "1737644419602",  # Simulating a timestamp
        "page": 1,
        "start": 0,
        "limit": 100,
        "token": token,
        "sel_language": "4_4",
        "cloud_id": cloud_id,
    }
    cookies = {"Token": token}
    response = requests.get(
        url,
        headers=HEADERS_URL_ENCODED,
        params=params,
        cookies=cookies
    )
    if response.status_code == 200:
        return response.json()
    else:
        raise Exception("Failed to fetch vouchers")


def create_voucher(token, base_url, cloud_id, realm_id, profile_id, quantity):
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
