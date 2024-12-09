from random import randint

import requests
import json

# API base URL
BASE_URL = 'http://localhost:8000/api/v1'
TOKEN_URL = f'{BASE_URL}/user/token/'
USER_ME_URL = f'{BASE_URL}/user/me/'
WALLET_URL = f'{BASE_URL}/wallet/'
SMART_CONTRACT_URL = f'{BASE_URL}/contract/'

# User credentials
USER_EMAIL = 'keeganthomaswhite@gmail.com'
USER_PASSWORD = 'M@ster789@'

# Global variable for storing the token
token = None

def create_wallet_for_user(email, password, wallet_name):
    payload = {
        'email': email,
        'password': password
    }
    response = requests.post(TOKEN_URL, json=payload)
    response.raise_for_status()
    token_data = response.json()
    token_new_wallet = token_data.get('token')
    wallet_data = {
        "name": wallet_name,
    }
    headers = {
        'accept': 'application/json',
        'Authorization': f'Bearer {token_new_wallet}',
        'Content-Type': 'application/json'
    }
    response = requests.post(WALLET_URL, json=wallet_data, headers=headers)
    if response:
        print("Wallet created successfully:", response.json())
        rsp = response.json()
        data = {
            'id': rsp.get('id'),
            'address': rsp.get('address'),
        }
        return data # Return the wallet ID for further use
    else:
        print("Failed to create wallet.")
        return None


def create_wallet():
    """Create a new wallet for the authenticated user."""
    wallet_data = {
        "name": "New Test Wallet"
    }
    response = handle_request('post', WALLET_URL, wallet_data)
    if response:
        print("Wallet created successfully:", response)
        return response.get('id')  # Return the wallet ID for further use
    else:
        print("Failed to create wallet.")
        return None


def update_wallet(wallet_id):
    """Update the name of an existing wallet."""
    update_url = f"{WALLET_URL}{wallet_id}/"
    update_data = {
        "name": "Updated Wallet Name"
    }
    response = handle_request('patch', update_url, update_data)
    if response:
        print("Wallet updated successfully:", response)
    else:
        print("Failed to update wallet.")


def create_user_req(email, password, username, first_name, last_name):
    send_url = f"{BASE_URL}/user/create/"
    send_data = {
        "email": email,
        "username": username,
        'first_name': first_name,
        'password': password,
        'last_name': last_name,
    }
    response = handle_request('post', send_url, send_data)
    print(response)

def send_krone_from_inethi(amount, recipient_address):
    """send krone from the iNethi wallet to another wallet"""
    send_url = f"{WALLET_URL}7/send-token/"
    send_data = {
        "recipient_address": recipient_address,
        "amount": amount
    }
    token_payload = {
        'email': 'inethi@inethi.com',
        'password': 'iNethi2023#'
    }
    response = requests.post(TOKEN_URL, json=token_payload)
    token_data = response.json()
    inethi_token = token_data.get('token')
    headers = {
        'accept': 'application/json',
        'Authorization': f'Bearer {inethi_token}',
        'Content-Type': 'application/json'
    }
    response = requests.post(send_url, json=send_data, headers=headers)
    print(response.json())


def account_index_add(user_to_add, email, password):
    send_url = f"{SMART_CONTRACT_URL}1/registry-add/"
    token_payload = {
        'email': email,
        'password': password,
    }
    response = requests.post(TOKEN_URL, json=token_payload)
    token_data = response.json()
    user_token = token_data.get('token')
    headers = {
        'accept': 'application/json',
        'Authorization': f'Bearer {user_token}',
        'Content-Type': 'application/json'
    }

    payload = {
        'address': user_to_add,
    }
    response = requests.post(send_url, json=payload, headers=headers)
    print(response.json())


def send_tokens_from_wallet(wallet_id, recipient_address, amount):
    """Attempt to send tokens from a wallet not owned by the authenticated user."""
    send_url = f"{WALLET_URL}{wallet_id}/send-token/"
    send_data = {
        "recipient_address": recipient_address,
        "amount": amount
    }
    print('inside send_tokens_from_wallet')
    response = handle_request('post', send_url, send_data)
    if response:
        print("Send token response:", response)
    else:
        print("Failed to send tokens. You may not own this wallet or there was another issue.")


def get_token():
    """Get a new token from the API."""
    global token
    payload = {
        'email': USER_EMAIL,
        'password': USER_PASSWORD
    }
    try:
        response = requests.post(TOKEN_URL, json=payload)
        response.raise_for_status()
        token_data = response.json()
        token = token_data.get('token')
        print("Token retrieved successfully.")
    except requests.RequestException as e:
        print(f"Error getting token: {e}")
        token = None


def get_headers():
    """Return the headers with the Authorization token."""
    if not token:
        get_token()
    return {
        'accept': 'application/json',
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json'
    }


def handle_request(method, url, data=None):
    """Generic function to handle API requests with token refresh logic."""
    global token
    response = ''
    try:
        headers = get_headers()
        if method.lower() == 'get':
            response = requests.get(url, headers=headers)
        elif method.lower() == 'post':
            response = requests.post(url, json=data, headers=headers)
        elif method.lower() == 'patch':
            response = requests.patch(url, json=data, headers=headers)
        elif method.lower() == 'put':
            response = requests.put(url, json=data, headers=headers)
        else:
            raise ValueError(f"Unsupported method: {method}")

        # If unauthorized, fetch a new token and retry once
        if response.status_code == 401:
            print("Token expired or invalid. Fetching a new token...")
            get_token()
            headers = get_headers()
            if method.lower() == 'get':
                response = requests.get(url, headers=headers)
            elif method.lower() == 'post':
                response = requests.post(url, json=data, headers=headers)
            elif method.lower() == 'patch':
                response = requests.patch(url, json=data, headers=headers)
            elif method.lower() == 'put':
                response = requests.put(url, json=data, headers=headers)

        response.raise_for_status()
        return response.json()

    except requests.RequestException as e:
        print(f"Error making request to {url}: {e}")
        if response.content:
            print(f"Response content: {response.content}")
        return None


def give_to_from_inethi(give_to_address):
    send_url = f"{SMART_CONTRACT_URL}2/faucet-give-to/"
    send_data = {
        "address": give_to_address,
    }
    token_payload = {
        'email': 'inethi@inethi.com',
        'password': 'iNethi2023#'
    }
    response = requests.post(TOKEN_URL, json=token_payload)
    token_data = response.json()
    inethi_token = token_data.get('token')
    headers = {
        'accept': 'application/json',
        'Authorization': f'Bearer {inethi_token}',
        'Content-Type': 'application/json'
    }
    response = requests.post(send_url, json=send_data, headers=headers)
    print(response.json())

def test_all_basic_func(email, password, username, first_name, last_name, wallet_name, send_to_addr):
    create_user_req(email, password, username, first_name, last_name)
    wallet_rsp = create_wallet_for_user(email, password, wallet_name)
    if wallet_rsp:
        print('SENDING FROM INETHI WALLET')
        send_krone_from_inethi(0.001, wallet_rsp['address'])
        print('###########################')
        print()
        print('GETTING TOKEN')
        payload = {
            'email': email,
            'password': password
        }
        response = requests.post(TOKEN_URL, json=payload)
        response.raise_for_status()
        token_data = response.json()
        token_new_wallet = token_data.get('token')
        headers = {
            'accept': 'application/json',
            'Authorization': f'Bearer {token_new_wallet}',
            'Content-Type': 'application/json'
        }
        print('###########################')
        print()

        print('SENDING TOKENS FROM NEW WALLET')
        send_url = f"{WALLET_URL}{wallet_rsp['id']}/send-token/"
        send_data = {
            "recipient_address": send_to_addr,
            "amount": 0.001
        }

        rsp = requests.post(send_url, json=send_data, headers=headers)
        print(rsp.json())
        print('###########################')
        print()

def check_registry(address, email, password):
    send_url = f"{SMART_CONTRACT_URL}1/registry-check-active/"
    send_data = {
        "address": address,
    }
    token_payload = {
        'email': email,
        'password': password
    }
    response = requests.post(TOKEN_URL, json=token_payload)
    token_data = response.json()
    user_token = token_data.get('token')
    headers = {
        'accept': 'application/json',
        'Authorization': f'Bearer {user_token}',
        'Content-Type': 'application/json'
    }

    response = requests.post(send_url, json=send_data, headers=headers)
    print(response.json())

def faucet_balance(email, password):
    url = f"{SMART_CONTRACT_URL}2/faucet-balance/"
    token_payload = {
        'email': email,
        'password': password
    }
    response = requests.post(TOKEN_URL, json=token_payload)
    token_data = response.json()
    user_token = token_data.get('token')
    headers = {
        'accept': 'application/json',
        'Authorization': f'Bearer {user_token}',
        'Content-Type': 'application/json'
    }
    response = requests.post(url, headers=headers)
    print(response.json())

def faucet_next_time(email, password):
    url = f"{SMART_CONTRACT_URL}2/faucet-next-time/"
    token_payload = {
        'email': email,
        'password': password
    }
    response = requests.post(TOKEN_URL, json=token_payload)
    token_data = response.json()
    user_token = token_data.get('token')
    headers = {
        'accept': 'application/json',
        'Authorization': f'Bearer {user_token}',
        'Content-Type': 'application/json'
    }
    response = requests.post(url, headers=headers)
    print(response.json())

def faucet_gimme(email, password):
    url = f"{SMART_CONTRACT_URL}2/faucet-gimme/"
    token_payload = {
        'email': email,
        'password': password
    }
    response = requests.post(TOKEN_URL, json=token_payload)
    token_data = response.json()
    user_token = token_data.get('token')
    headers = {
        'accept': 'application/json',
        'Authorization': f'Bearer {user_token}',
        'Content-Type': 'application/json'
    }
    response = requests.post(url, headers=headers)
    print(response.json())

def main():
    # Get user information
    # send_krone_from_inethi(0.01,'0x783782C82803b9426E013f5B05d5Cd4aa7809489')

    ####################### CREATE USER ########################
    # print('######################## CREATING USER ########################')
    # create_user_req('test_auto_gifter@inethi.com', 'iNethi2023#', username='inethi_auto_gas_test',
    #                 first_name='Test Auto Gase', last_name='User')
    # print('################################################')
    # print('######################## CREATE WALLET ########################')
    # wallet_id = create_wallet_for_user('test_auto_gifter@inethi.com', 'iNethi2023#',
    #                                    'inethi_auto_gas_test')
    # print(wallet_id)
    ######################## USE TO UPDATE USER ETC ########################
    # user_info = handle_request('get', USER_ME_URL)
    # if user_info:
    #     print("User Info:", user_info)
    #
    # # Update user information using PATCH
    # patch_data = {
    #     "email": "keeganthomaswhite@gmail.com",
    #     "username": "keeganwhite",
    #     "first_name": "keegan",
    #     "password": "M@ster789@"  # Ensure password is included
    # }
    # print('Running patch request')
    # updated_user_info = handle_request('patch', USER_ME_URL, patch_data)
    # if updated_user_info:
    #     print("Updated User Info (PATCH):", updated_user_info)
    # print('########')
    # # Update user information using PUT
    # put_data = {
    #     "email": "keeganthomaswhite@gmail.com",
    #     "username": "keeganwhite",
    #     "first_name": "KEEG",
    #     "last_name": "White",
    #     "password": "M@ster789@"
    # }
    # print('Running PUT')
    # updated_user_info_put = handle_request('put', USER_ME_URL, put_data)
    # if updated_user_info_put:
    #     print("Updated User Info (PUT):", updated_user_info_put)

    ######################## USE TO CHECK WALLET METHODS ########################
    # print('########')
    # print('Running Wallet methods')
    #
    # # Get wallet information
    # wallet_info = handle_request('get', WALLET_URL)
    # if wallet_info:
    #     print("Wallet Info:", wallet_info[0])
    #     wallet_info = wallet_info[0]
    #     print('test sending from a wallet you do not own. This should fail!')
    #     send_tokens_from_wallet(7, amount=0.1, recipient_address=wallet_info['address'])
    #     print('#######')
    #     print()
    #     print('Send should pass now:')
    #     send_tokens_from_wallet(wallet_info['id'], amount=0.001,
    #                             recipient_address='0xb89222b1B2fdE607e28B3c1C06BDA2696C3f0765')
    #
    # else:
    #     wallet_id = create_wallet()
    #     if wallet_id:
    #         # Test updating the wallet
    #         wallet_info = handle_request('get', WALLET_URL)
    #         print(wallet_info)

    ######################## USE TO TEST ACCOUNT INDEX ########################
    # print('Testing account index methods')
    # user_info = handle_request('get', USER_ME_URL)
    # if user_info:
    #     print("User Info:", user_info)
    # print()
    # account_index_add('0x783782C82803b9426E013f5B05d5Cd4aa7809489', 'keeganthomaswhite@gmail.com', 'M@ster789@')
    #
    # print('########################')
    # print('######################## GIVE TO FAUCET ########################')
    # give_to_from_inethi('0x3C42910f7c127772447d83b1fde0c57cD3582973')
    # random_num = randint(5,1000000000000000)
    # test_all_basic_func(f'full_test_{random_num}@inethi.com', 'iNethi2023#', f'full_test_{random_num}',
    #                     f'full_test_{random_num}', f'full_test_{random_num}', f'full_test_{random_num}',
    #                     '0xb89222b1B2fdE607e28B3c1C06BDA2696C3f0765')
    address = "0xb89222b1B2fdE607e28B3c1C06BDA2696C3f0765"
    email = 'inethi@inethi.com'
    password = 'iNethi2023#'
    faucet_balance(email, password)
    # faucet_next_time(email, password)
    # faucet_gimme(email, password)
    #
    # email = 'keeganthomaswhite@gmail.com'
    # password = 'M@ster789@'
    # faucet_balance(email, password)
    # faucet_next_time(email, password)
    # faucet_gimme(email, password)
    # check_registry(address, email, password)

if __name__ == '__main__':
    main()
