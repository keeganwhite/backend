import logging
from sigscale_ocs import OCSClient, ServiceInventory, ProductInventory, BalanceManagement, ProductCatalog
from sigscale_ocs.exceptions import OCSAPIError, AuthenticationError, BadRequestError, NotFoundError, ServerError

logger = logging.getLogger(__name__)


class OCSClientManager:
    """
    Manager for OCS client connections.
    Caches clients per OCS instance to avoid reconnection overhead.
    """
    _clients = {}
    
    @classmethod
    def get_client(cls, ocs_instance):
        """
        Get or create an OCS client for the given instance.
        
        Args:
            ocs_instance: OCSInstance model instance
            
        Returns:
            OCSClient: Configured OCS client
        """
        instance_id = ocs_instance.id
        
        if instance_id not in cls._clients:
            # Create new client with instance configuration
            client = OCSClient(
                base_url=ocs_instance.base_url,
                username=ocs_instance.username,
                password=ocs_instance.password,
                verify_ssl=ocs_instance.verify_ssl
            )
            cls._clients[instance_id] = client
            logger.debug(f"Created new OCS client for instance: {ocs_instance.name}")
        
        return cls._clients[instance_id]
    
    @classmethod
    def clear_client(cls, ocs_instance):
        """
        Clear cached client for an instance.
        Useful when instance credentials are updated.
        
        Args:
            ocs_instance: OCSInstance model instance
        """
        instance_id = ocs_instance.id
        if instance_id in cls._clients:
            client = cls._clients[instance_id]
            try:
                client.close()
            except Exception as e:
                logger.warning(f"Error closing OCS client: {e}")
            del cls._clients[instance_id]
            logger.debug(f"Cleared OCS client for instance: {ocs_instance.name}")


class OCSAPIClient:
    """
    High-level OCS API client that provides business logic methods.
    """
    
    def __init__(self, ocs_instance):
        self.ocs_instance = ocs_instance
        self.client = OCSClientManager.get_client(ocs_instance)
        self.service_inventory = ServiceInventory(self.client)
        self.product_inventory = ProductInventory(self.client)
        self.balance_mgmt = BalanceManagement(self.client)
        self.product_catalog = ProductCatalog(self.client)
    
    def create_subscriber(self, imsi, phone_number, offering_id, initial_balance_bytes=1000000000):
        """
        Create a new subscriber with initial balance.
        
        Args:
            imsi (str): SIM card IMSI (15 digits)
            phone_number (str): Phone number in international format
            offering_id (str): Product offering ID for data plan
            initial_balance_bytes (int): Initial balance in bytes (default: 1GB)
            
        Returns:
            dict: {
                "service_id": str,
                "product_id": str,
                "balance_adjustment_id": str,
                "success": bool,
                "error": str (if any)
            }
        """
        logger.debug(f"Creating subscriber with IMSI: {imsi}, Phone: {phone_number}, Offering ID: {offering_id}")
        try:
            # Step 1: Create subscriber/service
            service_data = {
                "name": f"Subscriber {phone_number}",
                "description": f"SIM card subscriber with IMSI {imsi}",
                "serviceCharacteristic": [
                    {"name": "IMSI", "value": imsi},
                    {"name": "MSISDN", "value": phone_number}
                ]
            }

            service = self.service_inventory.create_service(service_data)
            service_id = service["id"]

            # Step 2: Create product subscription (data plan)
            logger.debug(f"Creating product with offering ID: {offering_id}")
            
            product_data = {
                "name": f"Data Plan for {phone_number}",
                "description": f"Data subscription for subscriber {phone_number}",
                "productOffering": {"id": offering_id}
            }

            logger.debug(f"Creating product with data: {product_data}")
            try:
                product = self.product_inventory.create_product(product_data)
                product_id = product["id"]
                logger.debug(f"Created product with ID: {product_id}")
            except Exception as e:
                logger.error(f"Error creating product: {str(e)}")
                logger.error(f"Product data was: {product_data}")
                return {
                    "success": False,
                    "error": f"Failed to create product: {str(e)}"
                }

            # Step 3: Add initial balance
            logger.debug(f"Adding initial balance: {initial_balance_bytes} bytes to product {product_id}")
            
            # Try different parameter formats for balance adjustment
            try:
                # First try with the current format
                balance_adjustment = self.balance_mgmt.create_adjustment(
                    product_id=product_id,
                    amount=initial_balance_bytes,
                    units="bytes",
                    description=f"Initial balance for {phone_number}"
                )
                logger.debug(f"Created balance adjustment: {balance_adjustment}")
            except Exception as e:
                logger.error(f"Error creating balance adjustment with current format: {str(e)}")
                logger.error(f"Trying alternative format...")
                
                try:
                    # Try without units parameter
                    balance_adjustment = self.balance_mgmt.create_adjustment(
                        product_id=product_id,
                        amount=initial_balance_bytes,
                        description=f"Initial balance for {phone_number}"
                    )
                    logger.debug(f"Created balance adjustment (no units): {balance_adjustment}")
                except Exception as e2:
                    logger.error(f"Error with alternative format: {str(e2)}")
                    return {
                        "success": False,
                        "error": f"Failed to create balance adjustment: {str(e)} (Alternative: {str(e2)})"
                    }

            return {
                "service_id": service_id,
                "product_id": product_id,
                "balance_adjustment_id": balance_adjustment.get("id"),
                "success": True,
                "error": None
            }

        except Exception as e:
            logger.error(f"Error creating subscriber: {str(e)}")
            logger.error(f"Error type: {type(e).__name__}")
            logger.error(f"Error details: {str(e)}")
            return {
                "service_id": None,
                "product_id": None,
                "balance_adjustment_id": None,
                "success": False,
                "error": str(e)
            }
    
    def top_up_balance(self, product_id, amount_bytes, description="Balance top-up"):
        """
        Add balance to an existing subscriber's account.
        
        Args:
            product_id (str): Product subscription ID
            amount_bytes (int): Amount to add in bytes
            description (str): Description for the transaction
            
        Returns:
            dict: {
                "success": bool,
                "adjustment_id": str,
                "new_balance": str,
                "error": str (if any)
            }
        """
        try:
            # Create balance adjustment
            adjustment = self.balance_mgmt.create_adjustment(
                product_id=product_id,
                amount=amount_bytes,
                units="bytes",
                description=description
            )

            # Get updated balance
            buckets = self.balance_mgmt.list_buckets(product_id)
            total_balance = 0
            for bucket in buckets:
                remaining_amount = bucket.get('remaining_amount', '0')
                if remaining_amount != 'N/A':
                    total_balance += int(remaining_amount)

            return {
                "success": True,
                "adjustment_id": adjustment.get("id"),
                "new_balance": f"{total_balance / (1024*1024*1024):.2f} GB",
                "error": None
            }

        except Exception as e:
            logger.error(f"Error topping up balance: {str(e)}")
            return {
                "success": False,
                "adjustment_id": None,
                "new_balance": None,
                "error": str(e)
            }
    
    def get_subscriber_balance(self, product_id):
        """
        Get current balance for a subscriber.
        
        Args:
            product_id (str): Product subscription ID
            
        Returns:
            dict: Balance information
        """
        try:
            buckets = self.balance_mgmt.list_buckets(product_id)
            
            total_balance = 0
            balance_details = []
            
            for bucket in buckets:
                remaining_amount = bucket.get('remaining_amount', '0')
                if remaining_amount != 'N/A':
                    amount = int(remaining_amount)
                    total_balance += amount
                    balance_details.append({
                        "bucket_id": bucket.get("id"),
                        "remaining_amount": amount,
                        "remaining_amount_formatted": f"{amount / (1024*1024*1024):.2f} GB",
                        "unit": bucket.get("unit", "bytes")
                    })
            
            return {
                "success": True,
                "total_balance_bytes": total_balance,
                "total_balance_formatted": f"{total_balance / (1024*1024*1024):.2f} GB",
                "buckets": balance_details,
                "error": None
            }
            
        except Exception as e:
            logger.error(f"Error getting subscriber balance: {str(e)}")
            return {
                "success": False,
                "total_balance_bytes": 0,
                "total_balance_formatted": "0.00 GB",
                "buckets": [],
                "error": str(e)
            }
    
    def get_subscriber_info(self, service_id):
        """
        Get subscriber information and current balance.
        
        Args:
            service_id (str): Service/subscriber ID
            
        Returns:
            dict: Subscriber information with balance details
        """
        try:
            # Get subscriber details
            service = self.service_inventory.get_service(service_id)

            # Get associated products
            products = self.product_inventory.list_products()
            subscriber_products = [p for p in products if p.get("service", {}).get("id") == service_id]

            # Get balance for each product
            balance_info = []
            for product in subscriber_products:
                product_id = product["id"]
                balance_result = self.get_subscriber_balance(product_id)
                
                balance_info.append({
                    "product_id": product_id,
                    "product_name": product.get("name"),
                    "balance_bytes": balance_result.get("total_balance_bytes", 0),
                    "balance_formatted": balance_result.get("total_balance_formatted", "0.00 GB")
                })

            return {
                "success": True,
                "service": service,
                "products": subscriber_products,
                "balances": balance_info,
                "error": None
            }

        except Exception as e:
            logger.error(f"Error getting subscriber info: {str(e)}")
            return {
                "success": False,
                "service": None,
                "products": [],
                "balances": [],
                "error": str(e)
            }
    
    def list_product_offerings(self):
        """
        List all product offerings from the OCS server.
        
        Returns:
            dict: List of product offerings
        """
        try:
            offerings = self.product_catalog.list_offerings()
            return {
                "success": True,
                "offerings": offerings,
                "error": None
            }
        except Exception as e:
            logger.error(f"Error listing product offerings: {str(e)}")
            return {
                "success": False,
                "offerings": [],
                "error": str(e)
            }
    
    def close(self):
        """
        Close the OCS client connection.
        """
        try:
            self.client.close()
        except Exception as e:
            logger.warning(f"Error closing OCS client: {e}")
