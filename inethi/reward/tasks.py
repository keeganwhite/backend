from celery import shared_task
import logging
from django.conf import settings
from utils.crypto import CryptoUtils, decrypt_private_key
from network.utils import calculate_uptime_percentage
from reward.models import Reward, UptimeRewardTransaction
from core.models import Transaction, Wallet

logger = logging.getLogger('reward')


@shared_task
def process_reward(reward_id):
    """
    Calculate uptime for a given reward period, send tokens,
    and create a reward transaction.
    Logs all outcomes to rewards.log via the 'reward' logger.
    Always creates a reward transaction in the DB, but only sends
    tokens if awarded_amount > 0.
    """
    try:
        reward = Reward.objects.get(id=reward_id)
        logger.info(
            f"Processing reward {reward_id}: user {reward.user}, device {reward.device}"
        )

        # Ensure it's an uptime-based reward
        if reward.reward_type != "uptime" or not reward.device:
            logger.warning(
                f"Skipping reward {reward_id}, not uptime-based or missing device."
            )
            return

        # Determine the look-back period (from now - interval to now)
        interval_minutes = (
            reward.interval_minutes
        ) if not reward.once_off else 1440
        lookback_period = f"{interval_minutes} minutes"

        # Calculate uptime using the utility (handles missing pings as offline)
        uptime_percentage, total_pings, expected_pings = calculate_uptime_percentage(
            reward.device.id, lookback_period
        )
        logger.info(
            f"Calculated uptime for device {reward.device.id}: {uptime_percentage}% "
            f"over {expected_pings} expected pings."
        )

        # Calculate the awarded amount based on uptime percentage
        awarded_amount = float(uptime_percentage) * float(reward.reward_amount) / 100.0
        logger.info(f"Awarded amount for reward {reward_id}: {awarded_amount}")

        # --- Blockchain payout ---
        # Get network admin (owner) and device owner wallets
        network = reward.network
        if not network:
            logger.error(f"Reward {reward_id} has no associated network.")
            return
        network_admin = network.admin
        device_owner = reward.user

        # Get wallets
        admin_wallet = Wallet.objects.filter(user=network_admin).first()
        device_wallet = Wallet.objects.filter(user=device_owner).first()
        if not admin_wallet or not device_wallet:
            logger.error(
                f"Missing wallet for admin or device owner for reward {reward_id}."
            )
            return

        tx_receipt = None
        if awarded_amount > 0:
            # Decrypt admin private key
            admin_private_key = decrypt_private_key(admin_wallet.private_key)
            # Prepare CryptoUtils
            crypto_utils = CryptoUtils(
                contract_abi_path=settings.ABI_FILE_PATH,
                contract_address=settings.CONTRACT_ADDRESS,
                registry=settings.FAUCET_AND_INDEX_ENABLED,
                faucet=settings.FAUCET_AND_INDEX_ENABLED,
            )
            # Ensure admin has enough gas and is registered
            try:
                crypto_utils.pre_transaction_check(
                    private_key_admin=admin_private_key,
                    from_address=admin_wallet.address,
                    to_address=device_wallet.address,
                    amount=awarded_amount
                )
            except Exception as e:
                logger.error(f"Pre-transaction check failed for reward {reward_id}: {e}")
                return
            # Send tokens
            try:
                tx_receipt = crypto_utils.send_to_wallet_address(
                    from_address=admin_wallet.address,
                    private_key=admin_private_key,
                    to_address=device_wallet.address,
                    amount=awarded_amount
                )
                tx_hash = None
                if (
                    'transactionHash' in tx_receipt and
                        hasattr(
                            tx_receipt['transactionHash'], 'hex'
                            )
                        ):
                    tx_hash = tx_receipt['transactionHash'].hex()
                logger.info(
                    f"Blockchain transaction created for reward {reward_id}: "
                    f"tx_hash={tx_hash}"
                )
            except Exception as e:
                logger.error(f"Blockchain transfer failed for reward {reward_id}: {e}")
                return
        else:
            logger.info(
                f"No tokens sent for reward {reward_id} as awarded_amount is 0. "
                f"Recording reward transaction only."
            )

        # Create a reward transaction (record in DB)
        block_hash = None
        transaction_hash = None
        block_number = None
        gas_used = None
        if tx_receipt:
            if ('blockHash' in tx_receipt and
                    hasattr(tx_receipt['blockHash'], 'hex')):
                block_hash = tx_receipt['blockHash'].hex()
            if ('transactionHash' in tx_receipt and
                    hasattr(tx_receipt['transactionHash'], 'hex')):
                transaction_hash = tx_receipt['transactionHash'].hex()
            if 'blockNumber' in tx_receipt:
                block_number = tx_receipt['blockNumber']
            if 'gasUsed' in tx_receipt:
                gas_used = tx_receipt['gasUsed']

        transaction = Transaction.objects.create(
            sender=network_admin,
            recipient=device_owner,
            recipient_address=device_wallet.address,
            amount=awarded_amount,
            block_hash=block_hash,
            transaction_hash=transaction_hash,
            block_number=block_number,
            gas_used=gas_used,
            category='REWARD'
        )

        UptimeRewardTransaction.objects.create(
            reward=reward,
            transaction=transaction,
            uptime_seconds=interval_minutes * 60,
            percentage_awarded=uptime_percentage
        )
        logger.info(
            f"Successfully processed reward {reward.id} for device {reward.device.id} "
            f"with {awarded_amount} tokens sent."
        )

    except Reward.DoesNotExist:
        logger.error(f"Reward {reward_id} not found.")
    except Exception as e:
        logger.error(f"Error processing reward {reward_id}: {str(e)}")
