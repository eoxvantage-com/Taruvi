"""
Environment Variables Service Layer

Provides variable resolution, inheritance logic, caching, and access control
for the hierarchical environment variables system.
"""

from typing import Dict, Any, Optional, List
import logging
from django.core.cache import cache
from django.contrib.auth.models import User
from django.utils import timezone
from django.db import transaction

from .models import (
    SiteEnvironmentVariable, 
    AppEnvironmentVariable, 
    VariableAccessLog,
    EnvironmentVariablePermission
)

logger = logging.getLogger(__name__)


class EnvironmentVariableService:
    """
    Service for managing environment variables with inheritance and caching.
    
    Provides methods for resolving variables with site-to-app inheritance,
    access control, caching, and comprehensive audit logging.
    """
    
    # Cache TTL settings
    CACHE_TTL_CONFIG = 3600  # 1 hour for config variables
    CACHE_TTL_SECRET = 300   # 5 minutes for secrets
    CACHE_TTL_RESOLVED = 300  # 5 minutes for resolved variable sets
    
    def resolve_variables(
        self, 
        app_id: str,
        user_id: str,
        request_ip: str = '127.0.0.1',
        user_agent: str = 'Unknown'
    ) -> Dict[str, Any]:
        """
        Resolve all variables for an app with inheritance from site level.
        
        Args:
            app_id: Application ID to resolve variables for
            user_id: User ID for permission checking and audit logging
            request_ip: Client IP address for audit logging
            user_agent: User agent string for audit logging
            
        Returns:
            Dictionary of resolved variables with metadata
        """
        cache_key = f"resolved_vars:{app_id}:{user_id}"
        cached = cache.get(cache_key)
        if cached:
            logger.debug(f"Cache hit for resolved variables: {cache_key}")
            return cached
        
        try:
            # Get site-level variables
            site_vars = self._get_site_variables(user_id, request_ip, user_agent)
            
            # Get app-level variables  
            app_vars = self._get_app_variables(app_id, user_id, request_ip, user_agent)
            
            # Apply inheritance and override rules
            resolved = self._apply_inheritance(site_vars, app_vars)
            
            # Cache resolved variables (shorter TTL for security)
            cache.set(cache_key, resolved, self.CACHE_TTL_RESOLVED)
            
            logger.info(f"Resolved {len(resolved['variables'])} variables for app {app_id}")
            return resolved
            
        except Exception as e:
            logger.error(f"Error resolving variables for app {app_id}: {str(e)}")
            raise
    
    def get_variable(
        self,
        key: str,
        app_id: Optional[str] = None,
        user_id: str = None,
        request_ip: str = '127.0.0.1',
        user_agent: str = 'Unknown'
    ) -> Optional[Dict[str, Any]]:
        """
        Get a specific variable with inheritance resolution.
        
        Args:
            key: Variable key to retrieve
            app_id: Application ID (if None, only site-level is checked)
            user_id: User ID for permission checking
            request_ip: Client IP for audit logging
            user_agent: User agent for audit logging
            
        Returns:
            Variable data with metadata or None if not found/no access
        """
        try:
            # Try app-level first if app_id provided
            if app_id:
                app_var = self._get_app_variable(key, app_id, user_id, request_ip, user_agent)
                if app_var and app_var.get('overrides_site', False):
                    return app_var
            
            # Check site-level
            site_var = self._get_site_variable(key, user_id, request_ip, user_agent)
            
            # Return app-level if exists and doesn't override, otherwise site-level
            if app_id:
                app_var = self._get_app_variable(key, app_id, user_id, request_ip, user_agent)
                if app_var and not app_var.get('overrides_site', False):
                    return app_var
            
            return site_var
            
        except Exception as e:
            logger.error(f"Error getting variable {key}: {str(e)}")
            return None
    
    def set_variable(
        self,
        key: str,
        value: str,
        variable_type: str = 'config',
        description: str = '',
        app_id: Optional[str] = None,
        overrides_site: bool = False,
        user_id: str = None,
        request_ip: str = '127.0.0.1',
        user_agent: str = 'Unknown',
        metadata: Optional[Dict] = None
    ) -> bool:
        """
        Set a variable at site or app level.
        
        Args:
            key: Variable key
            value: Variable value
            variable_type: 'config' or 'secret'
            description: Variable description
            app_id: Application ID (if None, sets at site level)
            overrides_site: Whether app variable overrides site variable
            user_id: User ID for audit logging
            request_ip: Client IP for audit logging
            user_agent: User agent for audit logging
            metadata: Additional metadata
            
        Returns:
            True if successful, False otherwise
        """
        try:
            with transaction.atomic():
                if app_id:
                    # Set app-level variable
                    variable, created = AppEnvironmentVariable.objects.update_or_create(
                        app_id=app_id,
                        key=key,
                        defaults={
                            'variable_type': variable_type,
                            'description': description,
                            'overrides_site': overrides_site,
                            'metadata': metadata or {},
                            'modified_by_id': user_id,
                        }
                    )
                    variable.set_value(value)
                    variable.save()
                    scope = 'app'
                    variable_id = variable.id
                else:
                    # Set site-level variable
                    variable, created = SiteEnvironmentVariable.objects.update_or_create(
                        key=key,
                        defaults={
                            'variable_type': variable_type,
                            'description': description,
                            'metadata': metadata or {},
                            'modified_by_id': user_id,
                        }
                    )
                    variable.set_value(value)
                    variable.save()
                    scope = 'site'
                    variable_id = variable.id
                
                # Log the access
                self._log_access(
                    variable_id=variable_id,
                    variable_scope=scope,
                    variable_key=key,
                    user_id=user_id,
                    access_type='write',
                    request_ip=request_ip,
                    user_agent=user_agent,
                    response_status=200
                )
                
                # Invalidate relevant caches
                self._invalidate_caches(key, app_id)
                
                action = "Created" if created else "Updated"
                logger.info(f"{action} {scope} variable {key} for user {user_id}")
                return True
                
        except Exception as e:
            logger.error(f"Error setting variable {key}: {str(e)}")
            # Log failed access
            self._log_access(
                variable_id=None,
                variable_scope=scope if 'scope' in locals() else 'unknown',
                variable_key=key,
                user_id=user_id,
                access_type='write',
                request_ip=request_ip,
                user_agent=user_agent,
                response_status=500,
                error_message=str(e)
            )
            return False
    
    def delete_variable(
        self,
        key: str,
        app_id: Optional[str] = None,
        user_id: str = None,
        request_ip: str = '127.0.0.1',
        user_agent: str = 'Unknown'
    ) -> bool:
        """
        Delete a variable at site or app level.
        
        Args:
            key: Variable key to delete
            app_id: Application ID (if None, deletes from site level)
            user_id: User ID for audit logging
            request_ip: Client IP for audit logging
            user_agent: User agent for audit logging
            
        Returns:
            True if successful, False otherwise
        """
        try:
            with transaction.atomic():
                if app_id:
                    # Delete app-level variable
                    try:
                        variable = AppEnvironmentVariable.objects.get(app_id=app_id, key=key)
                        variable_id = variable.id
                        variable.delete()
                        scope = 'app'
                    except AppEnvironmentVariable.DoesNotExist:
                        return False
                else:
                    # Delete site-level variable
                    try:
                        variable = SiteEnvironmentVariable.objects.get(key=key)
                        variable_id = variable.id
                        variable.delete()
                        scope = 'site'
                    except SiteEnvironmentVariable.DoesNotExist:
                        return False
                
                # Log the access
                self._log_access(
                    variable_id=variable_id,
                    variable_scope=scope,
                    variable_key=key,
                    user_id=user_id,
                    access_type='delete',
                    request_ip=request_ip,
                    user_agent=user_agent,
                    response_status=200
                )
                
                # Invalidate relevant caches
                self._invalidate_caches(key, app_id)
                
                logger.info(f"Deleted {scope} variable {key} for user {user_id}")
                return True
                
        except Exception as e:
            logger.error(f"Error deleting variable {key}: {str(e)}")
            return False
    
    def _get_site_variables(self, user_id: str, request_ip: str, user_agent: str) -> Dict[str, Any]:
        """Get site variables user has permission to read."""
        cache_key = f"site_vars:{user_id}"
        cached = cache.get(cache_key)
        if cached:
            return cached
        
        variables = SiteEnvironmentVariable.objects.all().select_related()
        
        result = {}
        for var in variables:
            if self._check_read_permission(var, user_id, 'site'):
                result[var.key] = {
                    'value': var.get_value(),
                    'variable_type': var.variable_type,
                    'description': var.description,
                    'metadata': var.metadata,
                    'version': var.version,
                    'last_accessed_at': var.last_accessed_at.isoformat() if var.last_accessed_at else None,
                    'access_count': var.access_count,
                }
                # Log access and update tracking
                self._log_access(
                    variable_id=var.id,
                    variable_scope='site',
                    variable_key=var.key,
                    user_id=user_id,
                    access_type='read',
                    request_ip=request_ip,
                    user_agent=user_agent,
                    response_status=200
                )
                var.update_access_tracking()
        
        # Cache with appropriate TTL
        ttl = self.CACHE_TTL_SECRET if any(
            v.get('variable_type') == 'secret' for v in result.values()
        ) else self.CACHE_TTL_CONFIG
        cache.set(cache_key, result, ttl)
        
        return result
    
    def _get_app_variables(self, app_id: str, user_id: str, request_ip: str, user_agent: str) -> Dict[str, Any]:
        """Get app variables user has permission to read."""
        cache_key = f"app_vars:{app_id}:{user_id}"
        cached = cache.get(cache_key)
        if cached:
            return cached
        
        variables = AppEnvironmentVariable.objects.filter(
            app_id=app_id
        ).select_related()
        
        result = {}
        for var in variables:
            if self._check_read_permission(var, user_id, 'app'):
                result[var.key] = {
                    'value': var.get_value(),
                    'variable_type': var.variable_type,
                    'description': var.description,
                    'metadata': var.metadata,
                    'overrides_site': var.overrides_site,
                    'version': var.version,
                    'last_accessed_at': var.last_accessed_at.isoformat() if var.last_accessed_at else None,
                    'access_count': var.access_count,
                }
                # Log access and update tracking
                self._log_access(
                    variable_id=var.id,
                    variable_scope='app',
                    variable_key=var.key,
                    user_id=user_id,
                    access_type='read',
                    request_ip=request_ip,
                    user_agent=user_agent,
                    response_status=200
                )
                var.update_access_tracking()
        
        # Cache with appropriate TTL
        ttl = self.CACHE_TTL_SECRET if any(
            v.get('variable_type') == 'secret' for v in result.values()
        ) else self.CACHE_TTL_CONFIG
        cache.set(cache_key, result, ttl)
        
        return result
    
    def _get_site_variable(self, key: str, user_id: str, request_ip: str, user_agent: str) -> Optional[Dict[str, Any]]:
        """Get a specific site variable."""
        try:
            var = SiteEnvironmentVariable.objects.get(key=key)
            if self._check_read_permission(var, user_id, 'site'):
                # Log access and update tracking
                self._log_access(
                    variable_id=var.id,
                    variable_scope='site',
                    variable_key=var.key,
                    user_id=user_id,
                    access_type='read',
                    request_ip=request_ip,
                    user_agent=user_agent,
                    response_status=200
                )
                var.update_access_tracking()
                
                return {
                    'value': var.get_value(),
                    'variable_type': var.variable_type,
                    'description': var.description,
                    'metadata': var.metadata,
                    'version': var.version,
                    'source': 'site',
                }
        except SiteEnvironmentVariable.DoesNotExist:
            pass
        return None
    
    def _get_app_variable(self, key: str, app_id: str, user_id: str, request_ip: str, user_agent: str) -> Optional[Dict[str, Any]]:
        """Get a specific app variable."""
        try:
            var = AppEnvironmentVariable.objects.get(app_id=app_id, key=key)
            if self._check_read_permission(var, user_id, 'app'):
                # Log access and update tracking
                self._log_access(
                    variable_id=var.id,
                    variable_scope='app',
                    variable_key=var.key,
                    user_id=user_id,
                    access_type='read',
                    request_ip=request_ip,
                    user_agent=user_agent,
                    response_status=200
                )
                var.update_access_tracking()
                
                return {
                    'value': var.get_value(),
                    'variable_type': var.variable_type,
                    'description': var.description,
                    'metadata': var.metadata,
                    'overrides_site': var.overrides_site,
                    'version': var.version,
                    'source': 'app',
                }
        except AppEnvironmentVariable.DoesNotExist:
            pass
        return None
    
    def _apply_inheritance(self, site_vars: Dict, app_vars: Dict) -> Dict[str, Any]:
        """Apply inheritance rules to resolve final variable set."""
        resolved = {}
        
        # Start with site variables
        for key, var_data in site_vars.items():
            resolved[key] = {
                **var_data,
                'source': 'site',
                'inherited': True
            }
        
        # Apply app overrides and additions
        for key, var_data in app_vars.items():
            if var_data.get('overrides_site', False) and key in resolved:
                # App explicitly overrides site variable
                resolved[key] = {
                    **var_data,
                    'source': 'app', 
                    'overridden': True
                }
            elif key not in resolved:
                # App-specific variable
                resolved[key] = {
                    **var_data,
                    'source': 'app',
                    'app_specific': True
                }
            # If app variable exists but doesn't override, site takes precedence
        
        return {
            'variables': resolved,
            'metadata': {
                'total_variables': len(resolved),
                'inherited_count': sum(1 for v in resolved.values() if v.get('inherited', False)),
                'overridden_count': sum(1 for v in resolved.values() if v.get('overridden', False)),
                'app_specific_count': sum(1 for v in resolved.values() if v.get('app_specific', False)),
                'resolved_at': timezone.now().isoformat()
            }
        }
    
    def _check_read_permission(self, variable, user_id: str, scope: str) -> bool:
        """
        Check if user has read permission for variable.
        
        This is a placeholder for the actual permission checking logic
        that would integrate with the existing RBAC/ABAC system.
        """
        # TODO: Implement actual permission checking
        # For now, allow all reads (should be replaced with proper RBAC integration)
        return True
    
    def _log_access(
        self, 
        variable_id: Optional[str], 
        variable_scope: str, 
        variable_key: str,
        user_id: str, 
        access_type: str, 
        request_ip: str,
        user_agent: str,
        response_status: int,
        error_message: str = ''
    ) -> None:
        """Log variable access for audit trail."""
        try:
            VariableAccessLog.objects.create(
                variable_id=variable_id,
                variable_scope=variable_scope,
                variable_key=variable_key,
                user_id=user_id,
                access_type=access_type,
                client_ip=request_ip,
                user_agent=user_agent,
                response_status=response_status,
                error_message=error_message
            )
        except Exception as e:
            logger.error(f"Failed to log variable access: {str(e)}")
    
    def _invalidate_caches(self, key: str, app_id: Optional[str] = None) -> None:
        """Invalidate relevant cache entries when variables change."""
        try:
            # Invalidate site-level caches
            cache.delete_many([
                f"site_vars:*",
                f"resolved_vars:*",
            ])
            
            # Invalidate app-level caches if app_id provided
            if app_id:
                cache.delete_many([
                    f"app_vars:{app_id}:*",
                    f"resolved_vars:{app_id}:*",
                ])
            
            logger.debug(f"Invalidated caches for variable {key}")
        except Exception as e:
            logger.error(f"Failed to invalidate caches: {str(e)}")


# Singleton service instance
environment_service = EnvironmentVariableService()
