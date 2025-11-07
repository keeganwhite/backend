"""
RadiusDesk Client Manager with caching for efficient API usage.

This module provides a centralized way to manage RadiusDeskClient instances
with caching to avoid repeated authentications.
"""
import logging
from typing import Optional, Dict
from threading import Lock

from radiusdesk_api import RadiusDeskClient
from radiusdesk_api.exceptions import AuthenticationError, APIError

logger = logging.getLogger(__name__)


class RadiusDeskClientManager:
    """
    Manages RadiusDeskClient instances with caching per RadiusDeskInstance.

    Clients are cached by instance primary key to avoid repeated authentication
    calls. The cache is thread-safe and validates connections before returning
    cached clients.
    """

    _clients: Dict[int, RadiusDeskClient] = {}
    _lock = Lock()

    @classmethod
    def get_client(cls, instance) -> RadiusDeskClient:
        """
        Get or create a RadiusDeskClient for the given RadiusDeskInstance.

        Args:
            instance: RadiusDeskInstance model instance

        Returns:
            RadiusDeskClient: Configured and authenticated client

        Raises:
            AuthenticationError: If authentication fails
            APIError: If client creation fails
        """
        instance_pk = instance.pk

        with cls._lock:
            # Check if we have a cached client
            if instance_pk in cls._clients:
                client = cls._clients[instance_pk]
                # Validate the connection is still good
                try:
                    if client.check_connection():
                        logger.debug(
                            f"Using cached client for instance {instance.name}"
                        )
                        return client
                    else:
                        logger.debug(
                            f"Cached client for instance {instance.name} "
                            f"is invalid, creating new one"
                        )
                        # Remove invalid client from cache
                        del cls._clients[instance_pk]
                except Exception as e:
                    logger.warning(
                        f"Error checking cached client connection: {e}, "
                        f"creating new client"
                    )
                    # Remove problematic client from cache
                    if instance_pk in cls._clients:
                        del cls._clients[instance_pk]

            # Create new client
            try:
                logger.debug(
                    f"Creating new RadiusDeskClient for instance "
                    f"{instance.name}"
                )
                client = RadiusDeskClient(
                    base_url=instance.base_url,
                    username=instance.username,
                    password=instance.password,
                    cloud_id=str(instance.clouds.first().radius_desk_id)
                    if instance.clouds.exists()
                    else "1",
                    auto_login=True
                )

                # Update the instance token in the database
                instance.token = client.auth.token
                instance.save(update_fields=['token'])

                # Cache the client
                cls._clients[instance_pk] = client
                logger.debug(
                    f"Successfully created and cached client for instance "
                    f"{instance.name}"
                )
                return client

            except AuthenticationError as e:
                logger.error(
                    f"Authentication failed for instance {instance.name}: {e}"
                )
                raise
            except Exception as e:
                logger.error(
                    f"Failed to create client for instance {instance.name}: {e}"
                )
                raise

    @classmethod
    def clear_cache(cls, instance_pk: Optional[int] = None) -> None:
        """
        Clear cached clients.

        Args:
            instance_pk: If provided, clears only the client for this instance.
                        If None, clears all cached clients.
        """
        with cls._lock:
            if instance_pk is not None:
                if instance_pk in cls._clients:
                    del cls._clients[instance_pk]
                    logger.debug(
                        f"Cleared cached client for instance pk={instance_pk}"
                    )
            else:
                cls._clients.clear()
                logger.debug("Cleared all cached RadiusDesk clients")

    @classmethod
    def refresh_client(cls, instance) -> RadiusDeskClient:
        """
        Force refresh a client by clearing its cache and creating a new one.

        Args:
            instance: RadiusDeskInstance model instance

        Returns:
            RadiusDeskClient: Newly created and authenticated client

        Raises:
            AuthenticationError: If authentication fails
            APIError: If client creation fails
        """
        cls.clear_cache(instance.pk)
        return cls.get_client(instance)

