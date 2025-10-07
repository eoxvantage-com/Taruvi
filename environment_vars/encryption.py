"""
Encryption Utilities for Environment Variables

Provides tenant-aware encryption key management for django-encrypted-model-fields
with support for key rotation and secure key storage.
"""

import os
import logging
from typing import List, Optional, Tuple
from cryptography.fernet import Fernet
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured

logger = logging.getLogger(__name__)


class TenantKeyManager:
    """
    Manages encryption keys per tenant for secure environment variable storage.
    
    Provides methods for generating, retrieving, and rotating encryption keys
    with proper fallback mechanisms and security considerations.
    """
    
    @staticmethod
    def generate_tenant_keys(tenant_id: str) -> Tuple[str, str]:
        """
        Generate primary and rotation keys for a tenant.
        
        Args:
            tenant_id: Unique identifier for the tenant
            
        Returns:
            Tuple of (primary_key, rotation_key) as base64 encoded strings
        """
        primary_key = Fernet.generate_key().decode()
        rotation_key = Fernet.generate_key().decode()
        
        logger.info(f"Generated new encryption keys for tenant {tenant_id}")
        return primary_key, rotation_key
    
    @staticmethod
    def get_tenant_keys(tenant_id: Optional[str] = None) -> List[str]:
        """
        Get encryption keys for current or specified tenant.
        
        Args:
            tenant_id: Tenant ID to get keys for (if None, uses current tenant)
            
        Returns:
            List of encryption keys (primary first, then rotation keys)
        """
        if not tenant_id:
            # Try to get current tenant from django-tenants
            try:
                from django_tenants.utils import get_current_tenant
                tenant = get_current_tenant()
                tenant_id = str(tenant.id) if tenant else 'default'
            except Exception:
                tenant_id = 'default'
        
        keys = []
        
        # Primary key (most recent)
        primary_key = os.environ.get(f'TENANT_{tenant_id}_FERNET_KEY_1')
        if primary_key:
            keys.append(primary_key)
        
        # Rotation key (for seamless key rotation)
        rotation_key = os.environ.get(f'TENANT_{tenant_id}_FERNET_KEY_2')
        if rotation_key:
            keys.append(rotation_key)
        
        # Additional rotation keys (for extended rotation periods)
        for i in range(3, 6):  # Support up to 3 additional rotation keys
            rotation_key = os.environ.get(f'TENANT_{tenant_id}_FERNET_KEY_{i}')
            if rotation_key:
                keys.append(rotation_key)
        
        # Fallback to default key for development/testing
        if not keys:
            default_key = os.environ.get('DEFAULT_FERNET_KEY')
            if default_key:
                keys.append(default_key)
                logger.warning(f"Using default encryption key for tenant {tenant_id}")
            else:
                # Generate a default key for development if none exists
                if settings.DEBUG:
                    default_key = Fernet.generate_key().decode()
                    logger.warning(f"Generated temporary encryption key for development (tenant {tenant_id})")
                    keys.append(default_key)
                else:
                    raise ImproperlyConfigured(
                        f"No encryption keys found for tenant {tenant_id}. "
                        "Please set TENANT_{tenant_id}_FERNET_KEY_1 environment variable."
                    )
        
        return keys
    
    @staticmethod
    def rotate_tenant_keys(tenant_id: str) -> str:
        """
        Rotate encryption keys for a tenant.
        
        This moves the current primary key to rotation position and generates
        a new primary key. Old data remains decryptable with rotation keys.
        
        Args:
            tenant_id: Tenant ID to rotate keys for
            
        Returns:
            New primary key as base64 encoded string
        """
        # Get current keys
        current_keys = TenantKeyManager.get_tenant_keys(tenant_id)
        
        # Generate new primary key
        new_primary_key = Fernet.generate_key().decode()
        
        # Shift existing keys down (primary becomes rotation key 1, etc.)
        env_updates = {
            f'TENANT_{tenant_id}_FERNET_KEY_1': new_primary_key,
        }
        
        # Move existing keys to rotation positions
        for i, key in enumerate(current_keys[:4]):  # Keep max 4 old keys
            env_updates[f'TENANT_{tenant_id}_FERNET_KEY_{i + 2}'] = key
        
        # Log the rotation (don't log actual keys)
        logger.info(f"Rotated encryption keys for tenant {tenant_id}")
        logger.info(f"Key rotation requires updating environment variables: {list(env_updates.keys())}")
        
        return new_primary_key
    
    @staticmethod
    def validate_tenant_keys(tenant_id: str) -> bool:
        """
        Validate that tenant keys are properly configured and functional.
        
        Args:
            tenant_id: Tenant ID to validate keys for
            
        Returns:
            True if keys are valid and functional, False otherwise
        """
        try:
            keys = TenantKeyManager.get_tenant_keys(tenant_id)
            
            if not keys:
                logger.error(f"No encryption keys found for tenant {tenant_id}")
                return False
            
            # Test encryption/decryption with primary key
            test_data = "test_encryption_data"
            fernet = Fernet(keys[0].encode())
            
            encrypted = fernet.encrypt(test_data.encode())
            decrypted = fernet.decrypt(encrypted).decode()
            
            if decrypted != test_data:
                logger.error(f"Encryption test failed for tenant {tenant_id}")
                return False
            
            logger.debug(f"Encryption keys validated for tenant {tenant_id}")
            return True
            
        except Exception as e:
            logger.error(f"Key validation failed for tenant {tenant_id}: {str(e)}")
            return False


def get_encrypted_field_keys() -> List[str]:
    """
    Dynamically get encryption keys based on current tenant.
    
    This function is used by django-encrypted-model-fields to get the
    encryption keys for the current request context.
    
    Returns:
        List of encryption keys for the current tenant
    """
    try:
        return TenantKeyManager.get_tenant_keys()
    except Exception as e:
        logger.error(f"Failed to get encryption keys: {str(e)}")
        # Return empty list to prevent application crash
        # This will cause encryption to fail gracefully
        return []


def setup_encryption_keys() -> None:
    """
    Setup encryption keys for django-encrypted-model-fields.
    
    This function should be called during Django startup to configure
    the encryption system with tenant-aware key management.
    """
    try:
        # Override the package's key loading function
        import encrypted_model_fields.fields
        encrypted_model_fields.fields.get_keys = get_encrypted_field_keys
        
        logger.info("Configured tenant-aware encryption for django-encrypted-model-fields")
        
    except ImportError:
        logger.warning("django-encrypted-model-fields not installed, skipping encryption setup")
    except Exception as e:
        logger.error(f"Failed to setup encryption keys: {str(e)}")


# Initialize encryption setup when module is imported
setup_encryption_keys()