import requests
import json
import datetime
import logging
from django.conf import settings

logger = logging.getLogger(__name__)


class OneForYouClient:
    """
    Client for interacting with the 1FourYou API for voucher redemption.
    Handles OAuth token generation and voucher redemption operations.
    """
    
    _instance = None
    _access_token = None
    _token_expires_at = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(OneForYouClient, cls).__new__(cls)
        return cls._instance
    
    def __init__(self):
        # Only initialize once
        if not hasattr(self, '_initialized'):
            # Use single API key (base64-encoded) for v4 API
            self.api_key = getattr(settings, 'ONEFORYOU_API_KEY', None)
            # Fallback to old method for backward compatibility
            if not self.api_key:
                consumer_key = getattr(settings, 'ONEFORYOU_CONSUMER_KEY', None)
                consumer_secret = getattr(settings, 'ONEFORYOU_CONSUMER_SECRET', None)
                if consumer_key and consumer_secret:
                    # Generate base64 encoded key from consumer_key:consumer_secret
                    import base64
                    auth_string = f"{consumer_key}:{consumer_secret}"
                    self.api_key = base64.b64encode(auth_string.encode()).decode()
                    logger.warning("Using deprecated ONEFORYOU_CONSUMER_KEY/CONSUMER_SECRET. Please migrate to ONEFORYOU_API_KEY")
            
            self.user_id = getattr(settings, 'ONEFORYOU_USER_ID', None)
            self.account_number = getattr(settings, 'ONEFORYOU_ACCOUNT_NUMBER', None)
            
            # Determine environment (sandbox or production)
            environment = getattr(settings, 'ONEFORYOU_ENVIRONMENT', 'sandbox').lower()
            if environment == 'sandbox':
                self.base_url = "https://api-flashswitch-sandbox.flash-group.com"
            elif environment == 'production':
                self.base_url = "https://api.flashswitch.flash-group.com"
            else:
                logger.warning(f"Unknown ONEFORYOU_ENVIRONMENT '{environment}', defaulting to sandbox")
                self.base_url = "https://api-flashswitch-sandbox.flash-group.com"
            
            self.token_url = f"{self.base_url}/token"
            self.redeem_url = f"{self.base_url}/aggregation/4.0/1voucher/redeem"
            
            # Validate credentials are configured
            if not self.api_key:
                logger.error("1FourYou API key not configured: ONEFORYOU_API_KEY (or ONEFORYOU_CONSUMER_KEY/CONSUMER_SECRET) missing")
                raise ValueError("1FourYou API key must be configured in environment variables (ONEFORYOU_API_KEY)")
            
            if not self.account_number:
                logger.warning("ONEFORYOU_ACCOUNT_NUMBER not configured")
            
            account_info = f", Account: {self.account_number[:4]}..." if self.account_number else ""
            logger.debug(f"1FourYou client initialized - Environment: {environment}, Base URL: {self.base_url}{account_info}")
            self._initialized = True
    
    def generate_access_token(self):
        """
        Generate OAuth bearer token for 1FourYou API access.
        Uses cached token if still valid, otherwise requests a new one.
        
        Returns:
            str: Bearer token for API authentication
            
        Raises:
            Exception: If token generation fails
        """
        # Check if we have a valid cached token
        if (self._access_token and self._token_expires_at and 
            datetime.datetime.now() < self._token_expires_at):
            logger.debug("Using cached 1FourYou access token")
            return self._access_token
        
        try:
            # Use the base64-encoded API key directly (already encoded)
            headers = {
                'Authorization': f'Basic {self.api_key}',
                'Content-Type': 'application/x-www-form-urlencoded'
            }
            
            # Prepare OAuth request body with client_credentials grant type
            data = 'grant_type=client_credentials'
            
            # Request token
            logger.debug(f"Requesting 1FourYou access token from {self.token_url}")
            response = requests.post(self.token_url, headers=headers, data=data, timeout=30)
            
            if response.status_code == 200:
                response_data = response.json()
                access_token = response_data.get("access_token")
                expires_in = response_data.get("expires_in", 3600)  # Default to 1 hour
                
                if access_token:
                    # Cache the token with expiration time
                    self._access_token = access_token
                    self._token_expires_at = datetime.datetime.now() + datetime.timedelta(seconds=expires_in - 60)  # 1 minute buffer
                    
                    logger.debug(f"Successfully generated and cached 1FourYou access token (expires in {expires_in}s)")
                    return access_token
                else:
                    logger.error(f"No access_token in 1FourYou response: {response_data}")
                    raise Exception("No access_token in response")
            elif response.status_code == 401:
                logger.error(f"1FourYou authentication failed (401) - Invalid API key. Check ONEFORYOU_API_KEY")
                raise Exception(f"Authentication failed: Invalid API credentials (401)")
            elif response.status_code == 403:
                logger.error(f"1FourYou access forbidden (403) - Credentials may not have permission for v4 API. Contact Flash Integrations for v4 API access.")
                raise Exception(f"Access forbidden: Credentials may not have v4 API permissions (403)")
            else:
                logger.error(f"1FourYou token request failed: {response.status_code} - {response.text}")
                raise Exception(f"Token request failed: {response.status_code} - {response.text}")
                
        except Exception as e:
            logger.error(f"Error generating 1FourYou access token: {str(e)}")
            raise
    
    def clear_cached_token(self):
        """
        Clear the cached access token. Useful for testing or when token becomes invalid.
        """
        self._access_token = None
        self._token_expires_at = None
        logger.debug("Cleared cached 1FourYou access token")
    
    def _format_phone_number(self, phone_number):
        """
        Format phone number for 1FourYou API v4.
        Convert local format to exactly 11 digits starting with "27" (South Africa country code).
        
        Args:
            phone_number (str): Phone number in various formats
            
        Returns:
            str: Formatted phone number (11 digits, starting with 27)
        """
        # Remove any whitespace
        phone_number = phone_number.strip()
        
        # Remove + if present
        if phone_number.startswith('+'):
            phone_number = phone_number[1:]
        
        # If starts with 27, ensure it's exactly 11 digits
        if phone_number.startswith('27'):
            # Remove leading zeros after 27 if any
            digits = phone_number[2:]
            if len(digits) == 9:
                return phone_number  # Already 11 digits
            elif len(digits) < 9:
                # Pad with zeros if needed (shouldn't happen normally)
                return phone_number[:2] + digits.zfill(9)
        
        # If starts with 0, remove first digit and prepend 27
        if phone_number.startswith('0'):
            return "27" + phone_number[1:]
        
        # If already starts with numbers but not 0 or 27, assume it needs 27 prefix
        if phone_number.isdigit() and len(phone_number) == 9:
            return "27" + phone_number
        
        # Return as-is if already formatted (fallback)
        return phone_number
    
    def _generate_reference(self, voucher_pin, phone_number):
        """
        Generate unique reference for 1FourYou API v4.
        The reference must be unique for all transactions.
        
        Args:
            voucher_pin (str): Voucher PIN
            phone_number (str): Phone number (formatted)
            
        Returns:
            str: Unique reference ID
        """
        import hashlib
        
        current_time = datetime.datetime.now()
        timestamp_str = current_time.strftime("%Y%m%d%H%M%S%f")
        
        # Create a unique string combining all components
        unique_string = f"{voucher_pin}-{phone_number}-{timestamp_str}"
        
        # Generate hash for additional uniqueness
        hash_obj = hashlib.md5(unique_string.encode())
        hash_hex = hash_obj.hexdigest()[:8]
        
        # Combine timestamp and hash for a unique reference
        reference = f"ref-{timestamp_str}-{hash_hex}"
        
        return reference
    
    def redeem_voucher(self, voucher_pin, amount_cents, phone_number):
        """
        Redeem a 1FourYou voucher for the specified amount using API v4.
        
        Args:
            voucher_pin (str): The 1FourYou voucher PIN
            amount_cents (int): Amount to redeem in cents
            phone_number (str): Customer phone number (will be formatted)
            
        Returns:
            dict: API response containing:
                - reference: The transaction reference (for database storage)
                - responseCode: 0 for success, non-0 for error
                - responseMessage: Response message
                - voucher: Change voucher object if partial redemption (contains pin, amount, expiryDate, etc.)
            
        Raises:
            Exception: If redemption fails
        """
        try:
            # Get access token
            access_token = self.generate_access_token()
            
            # Format phone number to exactly 11 digits starting with 27
            formatted_phone = self._format_phone_number(phone_number) if phone_number else None
            
            # Generate unique reference
            reference = self._generate_reference(voucher_pin, formatted_phone or "")
            
            # Prepare redemption payload for v4 API
            payload = {
                "reference": reference,
                "accountNumber": self.account_number,
                "pin": voucher_pin,
                "amount": amount_cents,
                "storeId": "app",
                "terminalId": "app"
            }
            
            # Add mobileNumber if provided (optional field)
            if formatted_phone:
                payload["mobileNumber"] = formatted_phone
            
            headers = {
                'Authorization': f'Bearer {access_token}',
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            }
            
            logger.debug(f"Sending 1FourYou v4 redemption request - Reference: {reference}, PIN: {voucher_pin}, Amount: {amount_cents} cents")
            
            # Send redemption request
            response = requests.post(
                self.redeem_url, 
                headers=headers, 
                json=payload
            )
            
            # Parse response
            if response.status_code == 200:
                response_data = response.json()
                
                # Check responseCode (0 = success)
                response_code = response_data.get("responseCode", -1)
                
                if response_code == 0:
                    # Success - add reference to response for database storage
                    response_data["reference"] = reference
                    logger.debug(f"1FourYou redemption successful - Reference: {reference}, Response: {response_data}")
                    return response_data
                else:
                    # Error response with HTTP 200 but non-zero responseCode
                    error_msg = response_data.get("responseMessage", "Unknown error")
                    logger.error(f"1FourYou redemption failed - ResponseCode: {response_code}, Message: {error_msg}")
                    raise Exception(f"Redemption failed: {error_msg} (Code: {response_code})")
            elif response.status_code == 401:
                logger.error("1FourYou redemption failed (401) - Access token may be invalid or expired")
                raise Exception("Redemption failed: Authentication error (401) - Token may be invalid")
            elif response.status_code == 403:
                error_detail = response.text
                logger.error(f"1FourYou redemption failed (403) - Access forbidden to v4 API endpoint. Response: {error_detail}")
                logger.error("This typically means your API credentials don't have permission for the v4 API.")
                logger.error("Please contact Flash Integrations to enable v4 API access for your account.")
                raise Exception(f"Redemption failed: Access forbidden to v4 API (403). Your credentials may need v4 API permissions enabled by Flash Integrations.")
            else:
                # HTTP error
                error_msg = f"1FourYou redemption failed: {response.status_code} - {response.text}"
                logger.error(error_msg)
                raise Exception(error_msg)
                
        except Exception as e:
            logger.error(f"Error redeeming 1FourYou voucher: {str(e)}")
            raise
