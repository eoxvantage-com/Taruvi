"""
Environment Variables Admin Configuration

Provides Django admin interface for managing environment variables
with proper security considerations and audit trail integration.
"""

from typing import Any, List, Optional
from django.contrib import admin
from django.http import HttpRequest
from django.utils.html import format_html
from django.urls import reverse
from django.utils.safestring import mark_safe

from core.admin import BaseModelAdmin
from .models import (
    SiteEnvironmentVariable,
    AppEnvironmentVariable,
    EnvironmentVariablePermission,
    SecretRotationHistory,
    VariableAccessLog
)


@admin.register(SiteEnvironmentVariable)
class SiteEnvironmentVariableAdmin(BaseModelAdmin):
    """
    Admin interface for site-level environment variables.
    
    Provides secure management with masked secret values and
    comprehensive audit trail integration.
    """
    
    list_display = [
        'key', 'variable_type', 'description_truncated', 'version',
        'access_count', 'last_accessed_at', 'created_at'
    ]
    list_filter = ['variable_type', 'created_at', 'last_accessed_at']
    search_fields = ['key', 'description']
    readonly_fields = [
        'id', 'created_at', 'updated_at', 'created_by', 'modified_by',
        'last_accessed_at', 'access_count', 'version', 'encrypted_value_display'
    ]
    
    fieldsets = (
        ('Variable Information', {
            'fields': ('key', 'variable_type', 'description')
        }),
        ('Value', {
            'fields': ('value', 'encrypted_value_display'),
            'description': 'For security, encrypted values are not displayed in admin'
        }),
        ('Metadata', {
            'fields': ('metadata',),
            'classes': ('collapse',)
        }),
        ('Access Tracking', {
            'fields': ('version', 'access_count', 'last_accessed_at'),
            'classes': ('collapse',)
        }),
        ('Audit Trail', {
            'fields': ('id', 'created_at', 'updated_at', 'created_by', 'modified_by'),
            'classes': ('collapse',)
        }),
    )
    
    def description_truncated(self, obj: SiteEnvironmentVariable) -> str:
        """Return truncated description for list display."""
        if obj.description:
            return obj.description[:50] + '...' if len(obj.description) > 50 else obj.description
        return '-'
    description_truncated.short_description = 'Description'
    
    def encrypted_value_display(self, obj: SiteEnvironmentVariable) -> str:
        """Display masked encrypted value for security."""
        if obj.variable_type == 'secret' and obj.encrypted_value:
            return '••••••••••••••••'
        return 'N/A (Configuration variable)'
    encrypted_value_display.short_description = 'Encrypted Value'
    
    def get_readonly_fields(self, request: HttpRequest, obj: Optional[SiteEnvironmentVariable] = None) -> List[str]:
        """Customize readonly fields based on variable type."""
        readonly = list(self.readonly_fields)
        
        if obj and obj.variable_type == 'secret':
            # For secrets, make value field readonly to prevent accidental exposure
            readonly.append('value')
        elif obj and obj.variable_type == 'config':
            # For config, encrypted_value is not relevant
            pass
            
        return readonly
    
    def save_model(self, request: HttpRequest, obj: SiteEnvironmentVariable, form: Any, change: bool) -> None:
        """Override save to handle user tracking and value encryption."""
        if not change:  # Creating new object
            obj.created_by = request.user
        obj.modified_by = request.user
        
        # Handle value setting with proper encryption
        if 'value' in form.changed_data:
            obj.set_value(form.cleaned_data['value'])
        
        super().save_model(request, obj, form, change)


@admin.register(AppEnvironmentVariable)
class AppEnvironmentVariableAdmin(BaseModelAdmin):
    """
    Admin interface for app-level environment variables.
    
    Provides secure management with inheritance indicators and
    comprehensive audit trail integration.
    """
    
    list_display = [
        'key', 'app_id_short', 'variable_type', 'overrides_site',
        'description_truncated', 'version', 'access_count', 'created_at'
    ]
    list_filter = ['variable_type', 'overrides_site', 'created_at', 'last_accessed_at']
    search_fields = ['key', 'description', 'app_id']
    readonly_fields = [
        'id', 'created_at', 'updated_at', 'created_by', 'modified_by',
        'last_accessed_at', 'access_count', 'version', 'encrypted_value_display'
    ]
    
    fieldsets = (
        ('Variable Information', {
            'fields': ('app_id', 'key', 'variable_type', 'description', 'overrides_site')
        }),
        ('Value', {
            'fields': ('value', 'encrypted_value_display'),
            'description': 'For security, encrypted values are not displayed in admin'
        }),
        ('Metadata', {
            'fields': ('metadata',),
            'classes': ('collapse',)
        }),
        ('Access Tracking', {
            'fields': ('version', 'access_count', 'last_accessed_at'),
            'classes': ('collapse',)
        }),
        ('Audit Trail', {
            'fields': ('id', 'created_at', 'updated_at', 'created_by', 'modified_by'),
            'classes': ('collapse',)
        }),
    )
    
    def app_id_short(self, obj: AppEnvironmentVariable) -> str:
        """Return shortened app ID for list display."""
        return str(obj.app_id)[:8] + '...'
    app_id_short.short_description = 'App ID'
    
    def description_truncated(self, obj: AppEnvironmentVariable) -> str:
        """Return truncated description for list display."""
        if obj.description:
            return obj.description[:50] + '...' if len(obj.description) > 50 else obj.description
        return '-'
    description_truncated.short_description = 'Description'
    
    def encrypted_value_display(self, obj: AppEnvironmentVariable) -> str:
        """Display masked encrypted value for security."""
        if obj.variable_type == 'secret' and obj.encrypted_value:
            return '••••••••••••••••'
        return 'N/A (Configuration variable)'
    encrypted_value_display.short_description = 'Encrypted Value'
    
    def get_readonly_fields(self, request: HttpRequest, obj: Optional[AppEnvironmentVariable] = None) -> List[str]:
        """Customize readonly fields based on variable type."""
        readonly = list(self.readonly_fields)
        
        if obj and obj.variable_type == 'secret':
            # For secrets, make value field readonly to prevent accidental exposure
            readonly.append('value')
            
        return readonly
    
    def save_model(self, request: HttpRequest, obj: AppEnvironmentVariable, form: Any, change: bool) -> None:
        """Override save to handle user tracking and value encryption."""
        if not change:  # Creating new object
            obj.created_by = request.user
        obj.modified_by = request.user
        
        # Handle value setting with proper encryption
        if 'value' in form.changed_data:
            obj.set_value(form.cleaned_data['value'])
        
        super().save_model(request, obj, form, change)


@admin.register(EnvironmentVariablePermission)
class EnvironmentVariablePermissionAdmin(BaseModelAdmin):
    """Admin interface for environment variable permissions."""
    
    list_display = [
        'variable_id_short', 'variable_scope', 'role_id_short',
        'permission_type', 'created_at'
    ]
    list_filter = ['variable_scope', 'permission_type', 'created_at']
    search_fields = ['variable_id', 'role_id']
    readonly_fields = ['id', 'created_at', 'created_by']
    
    fieldsets = (
        ('Permission Details', {
            'fields': ('variable_id', 'variable_scope', 'role_id', 'permission_type')
        }),
        ('Audit Trail', {
            'fields': ('id', 'created_at', 'created_by'),
            'classes': ('collapse',)
        }),
    )
    
    def variable_id_short(self, obj: EnvironmentVariablePermission) -> str:
        """Return shortened variable ID for list display."""
        return str(obj.variable_id)[:8] + '...'
    variable_id_short.short_description = 'Variable ID'
    
    def role_id_short(self, obj: EnvironmentVariablePermission) -> str:
        """Return shortened role ID for list display."""
        return str(obj.role_id)[:8] + '...'
    role_id_short.short_description = 'Role ID'


@admin.register(SecretRotationHistory)
class SecretRotationHistoryAdmin(BaseModelAdmin):
    """Admin interface for secret rotation history."""
    
    list_display = [
        'variable_id_short', 'variable_scope', 'rotation_type',
        'old_version', 'new_version', 'rotated_at', 'rotated_by_short'
    ]
    list_filter = ['variable_scope', 'rotation_type', 'rotated_at']
    search_fields = ['variable_id', 'rotated_by', 'reason']
    readonly_fields = ['id', 'rotated_at']
    
    fieldsets = (
        ('Rotation Details', {
            'fields': ('variable_id', 'variable_scope', 'rotation_type', 'old_version', 'new_version')
        }),
        ('Audit Information', {
            'fields': ('rotated_at', 'rotated_by', 'reason')
        }),
        ('System Fields', {
            'fields': ('id',),
            'classes': ('collapse',)
        }),
    )
    
    def variable_id_short(self, obj: SecretRotationHistory) -> str:
        """Return shortened variable ID for list display."""
        return str(obj.variable_id)[:8] + '...'
    variable_id_short.short_description = 'Variable ID'
    
    def rotated_by_short(self, obj: SecretRotationHistory) -> str:
        """Return shortened rotated_by ID for list display."""
        return str(obj.rotated_by)[:8] + '...'
    rotated_by_short.short_description = 'Rotated By'


@admin.register(VariableAccessLog)
class VariableAccessLogAdmin(BaseModelAdmin):
    """Admin interface for variable access logs."""
    
    list_display = [
        'variable_key', 'variable_scope', 'access_type', 'user_id_short',
        'client_ip', 'response_status', 'access_time'
    ]
    list_filter = ['variable_scope', 'access_type', 'response_status', 'access_time']
    search_fields = ['variable_key', 'user_id', 'client_ip']
    readonly_fields = ['id', 'access_time']
    
    fieldsets = (
        ('Access Details', {
            'fields': ('variable_id', 'variable_scope', 'variable_key', 'access_type')
        }),
        ('User Information', {
            'fields': ('user_id', 'client_ip', 'user_agent')
        }),
        ('Response Information', {
            'fields': ('response_status', 'error_message')
        }),
        ('System Fields', {
            'fields': ('id', 'access_time'),
            'classes': ('collapse',)
        }),
    )
    
    def user_id_short(self, obj: VariableAccessLog) -> str:
        """Return shortened user ID for list display."""
        return str(obj.user_id)[:8] + '...'
    user_id_short.short_description = 'User ID'
    
    def has_add_permission(self, request: HttpRequest) -> bool:
        """Disable manual creation of access logs."""
        return False
    
    def has_change_permission(self, request: HttpRequest, obj: Optional[VariableAccessLog] = None) -> bool:
        """Disable editing of access logs."""
        return False
    
    def has_delete_permission(self, request: HttpRequest, obj: Optional[VariableAccessLog] = None) -> bool:
        """Allow deletion for log cleanup."""
        return request.user.is_superuser