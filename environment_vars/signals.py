"""
Environment Variables Signals

Provides Django signals for cache invalidation, audit logging,
and other reactive behaviors for environment variables.
"""

import logging
from django.db.models.signals import post_save, post_delete
from django.dispatch import receiver
from django.core.cache import cache

from .models import SiteEnvironmentVariable, AppEnvironmentVariable

logger = logging.getLogger(__name__)


@receiver(post_save, sender=SiteEnvironmentVariable)
def invalidate_site_variable_cache(sender, instance, created, **kwargs):
    """
    Invalidate relevant caches when site variables are created or updated.
    
    Args:
        sender: The model class (SiteEnvironmentVariable)
        instance: The actual instance being saved
        created: Boolean indicating if this is a new instance
        **kwargs: Additional keyword arguments
    """
    try:
        # Invalidate site-level caches
        cache_patterns = [
            'site_vars:*',
            'resolved_vars:*',
        ]
        
        for pattern in cache_patterns:
            cache.delete_many([pattern])
        
        action = "Created" if created else "Updated"
        logger.debug(f"{action} site variable {instance.key}, invalidated caches")
        
    except Exception as e:
        logger.error(f"Failed to invalidate cache for site variable {instance.key}: {str(e)}")


@receiver(post_delete, sender=SiteEnvironmentVariable)
def invalidate_site_variable_cache_on_delete(sender, instance, **kwargs):
    """
    Invalidate relevant caches when site variables are deleted.
    
    Args:
        sender: The model class (SiteEnvironmentVariable)
        instance: The actual instance being deleted
        **kwargs: Additional keyword arguments
    """
    try:
        # Invalidate site-level caches
        cache_patterns = [
            'site_vars:*',
            'resolved_vars:*',
        ]
        
        for pattern in cache_patterns:
            cache.delete_many([pattern])
        
        logger.debug(f"Deleted site variable {instance.key}, invalidated caches")
        
    except Exception as e:
        logger.error(f"Failed to invalidate cache for deleted site variable {instance.key}: {str(e)}")


@receiver(post_save, sender=AppEnvironmentVariable)
def invalidate_app_variable_cache(sender, instance, created, **kwargs):
    """
    Invalidate relevant caches when app variables are created or updated.
    
    Args:
        sender: The model class (AppEnvironmentVariable)
        instance: The actual instance being saved
        created: Boolean indicating if this is a new instance
        **kwargs: Additional keyword arguments
    """
    try:
        # Invalidate app-specific and resolved caches
        cache_patterns = [
            f'app_vars:{instance.app_id}:*',
            f'resolved_vars:{instance.app_id}:*',
        ]
        
        # If this variable overrides site variables, also invalidate site caches
        if instance.overrides_site:
            cache_patterns.extend([
                'site_vars:*',
                'resolved_vars:*',
            ])
        
        for pattern in cache_patterns:
            cache.delete_many([pattern])
        
        action = "Created" if created else "Updated"
        logger.debug(f"{action} app variable {instance.key} for app {instance.app_id}, invalidated caches")
        
    except Exception as e:
        logger.error(f"Failed to invalidate cache for app variable {instance.key}: {str(e)}")


@receiver(post_delete, sender=AppEnvironmentVariable)
def invalidate_app_variable_cache_on_delete(sender, instance, **kwargs):
    """
    Invalidate relevant caches when app variables are deleted.
    
    Args:
        sender: The model class (AppEnvironmentVariable)
        instance: The actual instance being deleted
        **kwargs: Additional keyword arguments
    """
    try:
        # Invalidate app-specific and resolved caches
        cache_patterns = [
            f'app_vars:{instance.app_id}:*',
            f'resolved_vars:{instance.app_id}:*',
        ]
        
        # If this variable was overriding site variables, also invalidate site caches
        if instance.overrides_site:
            cache_patterns.extend([
                'site_vars:*',
                'resolved_vars:*',
            ])
        
        for pattern in cache_patterns:
            cache.delete_many([pattern])
        
        logger.debug(f"Deleted app variable {instance.key} for app {instance.app_id}, invalidated caches")
        
    except Exception as e:
        logger.error(f"Failed to invalidate cache for deleted app variable {instance.key}: {str(e)}")