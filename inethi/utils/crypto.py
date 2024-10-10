import json

import web3
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
    def __init__(
            self,
            contract_abi_path: str,
            contract_address: str,
            registry: bool = False,
            faucet: bool = False
    ):
        self.w3 = Web3(Web3.HTTPProvider(settings.BLOCKCHAIN_PROVIDER_URL))
        self.contract = load_contract(contract_abi_path, contract_address)
        if registry:
            self.registry = load_contract(
                settings.REGISTRY_ABI_FILE_PATH,
                settings.REGISTRY_ADDRESS
            )
        else:
            self.registry = None
        if faucet:
            self.faucet = load_contract(
                settings.FAUCET_ABI_FILE_PATH,
                settings.FAUCET_ADDRESS
            )

    def create_wallet(self) -> dict:
        """Create a wallet on the blockchain."""
        account = self.w3.eth.account.create()
        return {
            'private_key': account._private_key.hex(),
            'address': account.address
        }

    def complete_transaction(
            self,
            private_key: str,
            transaction: dict
    ) -> TxReceipt:
        """
        Sign, hash and get transaction receipt.
        ---
        Required fields:
        - private_key: decrypted private key to sign transaction
        - transaction: transaction to sign
        returns receipt of transaction
        """
        signed_tx = self.w3.eth.account.sign_transaction(
            transaction,
            private_key=private_key
        )
        tx_hash = self.w3.eth.send_raw_transaction(signed_tx.raw_transaction)
        # Wait for the transaction to be mined
        receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
        return receipt

    def estimate_gas_for_transfer(
            self,
            contract: web3.eth.Contract,
            from_address: str,
            to_address: str,
            token_amount: int
    ) -> int:
        """Estimate the gas required for a transfer."""
        transfer_function = contract.functions.transfer(
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

        receipt = self.complete_transaction(private_key, tx)
        return receipt

    def balance_of(self, address: str) -> float:
        """Check the balance of a wallet."""
        raw_balance = self.contract.functions.balanceOf(address).call()
        decimals = self.contract.functions.decimals().call()
        return raw_balance / (10**decimals)

    def faucet_give_to(
            self,
            private_key: str,
            give_to_address: str
    ) -> TxReceipt:
        """Give tokens to an address registered in the account index"""
        account = self.w3.eth.account.from_key(private_key)
        sender_address = account.address

        nonce = self.w3.eth.get_transaction_count(sender_address)
        gas_price = self.w3.eth.gas_price

        gas_estimate = self.faucet.functions.giveTo(
            give_to_address
        ).estimate_gas({
            'from': sender_address
        })

        tx = self.faucet.functions.giveTo(
            give_to_address
        ).build_transaction(
            {
                'from': sender_address,
                'nonce': nonce,
                'gas': gas_estimate,
                'gasPrice': gas_price,
                'chainId': self.w3.eth.chain_id,
            }
        )

        receipt = self.complete_transaction(private_key, tx)

        if receipt:
            print("Transaction receipt:", receipt)
            return receipt
        else:
            raise Exception("Transaction failed")

    def account_index_check_active(self, address_to_check: str) -> bool:
        """Check if an address is active on the account index."""
        active = self.registry.functions.isActive(address_to_check).call()
        return active

    def registry_add(self, private_key: str, address_to_add: str) -> TxReceipt:
        """
        Add an address to a registry using the private key
        of the contract owner
        """
        account = self.w3.eth.account.from_key(private_key)
        sender_address = account.address

        nonce = self.w3.eth.get_transaction_count(sender_address)
        gas_price = self.w3.eth.gas_price
        gas_estimate = self.registry.functions.add(
            address_to_add
        ).estimate_gas({
            'from': sender_address
        })

        tx = self.registry.functions.add(address_to_add).build_transaction({
            'from': sender_address,
            'nonce': nonce,
            'gas': gas_estimate,
            'gasPrice': gas_price,
            'chainId': self.w3.eth.chain_id,
        })

        receipt = self.complete_transaction(private_key, tx)
        if receipt:
            print("Transaction receipt:", receipt)
            return receipt
        else:
            raise Exception("Transaction failed")
