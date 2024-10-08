import json
from cryptography.fernet import Fernet
from web3 import Web3
from django.conf import settings
from web3.types import TxReceipt


def encrypt_private_key(private_key: str) -> str:
    """Fernet encrypt a private key."""
    fernet = Fernet(settings.WALLET_ENCRYPTION_KEY)
    encrypted_key = fernet.encrypt(private_key.encode())
    return encrypted_key.decode()


def decrypt_private_key(encrypted_key: str) -> str:
    """Fernet decrypt a private key."""
    fernet = Fernet(settings.WALLET_ENCRYPTION_KEY)
    decrypted_key = fernet.decrypt(encrypted_key.encode())
    return decrypted_key.decode()


def load_contract(abi_path: str, contract_address: str):
    """Load contract from ABI file and contract address."""
    with open(abi_path, "r", encoding="utf-8") as abi_file:
        contract_abi = json.load(abi_file)

    w3 = Web3(Web3.HTTPProvider(settings.BLOCKCHAIN_PROVIDER_URL))
    contract = w3.eth.contract(address=contract_address, abi=contract_abi)
    return contract


class CryptoUtils:
    """Utility class for performing blockchain interactions"""
    def __init__(self, contract_abi_path: str, contract_address: str):
        self.w3 = Web3(Web3.HTTPProvider(settings.BLOCKCHAIN_PROVIDER_URL))
        self.contract = load_contract(contract_abi_path, contract_address)

    def create_wallet(self) -> dict:
        """Create a wallet on the blockchain."""
        account = self.w3.eth.account.create()
        return {
            'private_key': account._private_key.hex(),
            'address': account.address
        }

    def estimate_gas_for_transfer(
            self,
            from_address: str,
            to_address: str,
            token_amount: int
    ) -> int:
        """Estimate the gas required for a transfer."""
        transfer_function = self.contract.functions.transfer(
            to_address,
            token_amount
        )

        return transfer_function.estimate_gas(
            {'from': from_address}
        )

    def send_to_wallet_address(
            self,
            from_address: str,
            private_key: str,
            to_address: str,
            amount: float
    ) -> TxReceipt:
        """Send tokens to a wallet address."""
        # Calculate token amount adjusted for decimals
        decimals = self.contract.functions.decimals().call()
        token_amount = int(amount * (10**decimals))

        # Estimate gas and get current gas price
        gas = self.estimate_gas_for_transfer(
            from_address,
            to_address,
            token_amount
        )
        gas_price = self.w3.eth.gas_price

        # Prepare and sign the transaction
        nonce = self.w3.eth.get_transaction_count(from_address)
        transfer = self.contract.functions.transfer(to_address, token_amount)
        tx = transfer.build_transaction({
            'chainId': self.w3.eth.chain_id,
            'gas': gas,
            'gasPrice': gas_price,
            'nonce': nonce,
        })
        signed_tx = self.w3.eth.account.sign_transaction(
            tx,
            private_key  # decrypted private key
        )

        # Send the transaction and wait for the receipt
        tx_hash = self.w3.eth.send_raw_transaction(signed_tx.raw_transaction)
        return self.w3.eth.wait_for_transaction_receipt(tx_hash)

    def balance_of(self, address: str) -> float:
        """Check the balance of a wallet."""
        raw_balance = self.contract.functions.balanceOf(address).call()
        decimals = self.contract.functions.decimals().call()
        return raw_balance / (10**decimals)
