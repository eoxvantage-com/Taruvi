"""
Environment Variables Models

Provides hierarchical environment variables and secrets management with:
- Site-level variables that cascade to app-level
- Conditional encryption based on variable type
- Comprehensive audit logging and access tracking
- Secret rotation support with versioning
"""

from typing import Any, Dict, Optional
import uuid

from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
from django.core.exceptions import ValidationError
from encrypted_model_fields.fields import EncryptedTextField

from core.models import BaseModel


class SiteEnvironmentVariable(BaseModel):
    """
    Site-level environment variables that cascade to all apps within the site.
    
    Supports both public configuration and encrypted secrets with conditional
    encryption based on variable_type field.
    """
    
    VARIABLE_TYPE_CHOICES = [
        ('config', 'Configuration'),
        ('secret', 'Secret'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    # site_id is implicit via tenant schema
    key = models.CharField(
        max_length=255, 
        db_index=True,
        help_text="Variable key name (e.g., DATABASE_URL, API_TIMEOUT)"
    )
    
    # Conditional encryption based on variable_type
    value = models.TextField(
        blank=True,
        help_text="Plain text value for configuration variables"
    )
    encrypted_value = EncryptedTextField(
        null=True, 
        blank=True,
        help_text="Encrypted value for secret variables"
    )
    
    variable_type = models.CharField(
        max_length=20,
        choices=VARIABLE_TYPE_CHOICES,
        default='config',
        help_text="Type of variable - config (plain) or secret (encrypted)"
    )
    description = models.TextField(
        blank=True,
        help_text="Description of what this variable is used for"
    )
    
    # Access tracking
    last_accessed_at = models.DateTimeField(
        null=True, 
        blank=True,
        help_text="When this variable was last accessed"
    )
    access_count = models.PositiveIntegerField(
        default=0,
        help_text="Number of times this variable has been accessed"
    )
    
    # Versioning for secret rotation
    version = models.PositiveIntegerField(
        default=1,
        help_text="Version number for secret rotation tracking"
    )
    
    # Additional metadata
    metadata = models.JSONField(
        default=dict, 
        blank=True,
        help_text="Additional metadata (tags, rotation policy, etc.)"
    )
    
    class Meta:
        verbose_name = 'Site Environment Variable'
        verbose_name_plural = 'Site Environment Variables'
        unique_together = [['key']]  # Unique key per site (tenant)
        indexes = [
            models.Index(fields=['key']),
            models.Index(fields=['variable_type']),
            models.Index(fields=['created_at']),
            models.Index(fields=['last_accessed_at']),
        ]
        ordering = ['key']
    
    def __str__(self) -> str:
        """String representation showing key and type."""
        return f"{self.key} ({self.get_variable_type_display()})"
    
    def get_value(self) -> str:
        """
        Get decrypted value regardless of variable type.
        
        Returns:
            The actual value, decrypted if it's a secret
        """
        if self.variable_type == 'secret':
            return self.encrypted_value or ''
        return self.value
    
    def set_value(self, new_value: str) -> None:
        """
        Set value with appropriate encryption based on variable type.
        
        Args:
            new_value: The value to store
        """
        if self.variable_type == 'secret':
            self.encrypted_value = new_value
            self.value = ''  # Clear plaintext for security
        else:
            self.value = new_value
            self.encrypted_value = None
    
    def clean(self) -> None:
        """Validate the model."""
        super().clean()
        
        # Validate key format (alphanumeric, underscores, hyphens)
        import re
        if not re.match(r'^[A-Z0-9_-]+$', self.key):
            raise ValidationError({
                'key': 'Key must contain only uppercase letters, numbers, underscores, and hyphens'
            })
        
        # Ensure appropriate field is populated based on type
        if self.variable_type == 'secret':
            if not self.encrypted_value and not self.value:
                raise ValidationError({
                    'encrypted_value': 'Secret variables must have a value'
                })
        else:
            if not self.value:
                raise ValidationError({
                    'value': 'Configuration variables must have a value'
                })
    
    def save(self, *args, **kwargs) -> None:
        """Override save to handle encryption and validation."""
        self.full_clean()
        super().save(*args, **kwargs)
    
    def update_access_tracking(self) -> None:
        """Update access tracking fields."""
        self.last_accessed_at = timezone.now()
        self.access_count += 1
        self.save(update_fields=['last_accessed_at', 'access_count'])
    
    def rotate_secret(self, new_value: str, rotated_by: User, reason: str = '') -> 'SecretRotationHistory':
        """
        Rotate a secret value and create audit record.
        
        Args:
            new_value: New secret value
            rotated_by: User performing the rotation
            reason: Reason for rotation
            
        Returns:
            SecretRotationHistory record
            
        Raises:
            ValidationError: If variable is not a secret
        """
        if self.variable_type != 'secret':
            raise ValidationError("Only secret variables can be rotated")
        
        old_version = self.version
        self.version += 1
        self.set_value(new_value)
        self.modified_by = rotated_by
        self.save()
        
        # Create rotation history record
        return SecretRotationHistory.objects.create(
            variable_id=self.id,
            variable_scope='site',
            old_version=old_version,
            new_version=self.version,
            rotation_type='manual',
            rotated_by=rotated_by.id,
            reason=reason
        )


class AppEnvironmentVariable(BaseModel):
    """
    App-level environment variables with inheritance from site level.
    
    Can override site-level variables or define app-specific variables.
    Supports both public configuration and encrypted secrets.
    """
    
    VARIABLE_TYPE_CHOICES = [
        ('config', 'Configuration'),
        ('secret', 'Secret'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    app_id = models.UUIDField(
        db_index=True,
        help_text="Reference to the application this variable belongs to"
    )
    key = models.CharField(
        max_length=255, 
        db_index=True,
        help_text="Variable key name (e.g., DATABASE_URL, API_TIMEOUT)"
    )
    
    # Conditional encryption based on variable_type
    value = models.TextField(
        blank=True,
        help_text="Plain text value for configuration variables"
    )
    encrypted_value = EncryptedTextField(
        null=True, 
        blank=True,
        help_text="Encrypted value for secret variables"
    )
    
    variable_type = models.CharField(
        max_length=20,
        choices=VARIABLE_TYPE_CHOICES,
        default='config',
        help_text="Type of variable - config (plain) or secret (encrypted)"
    )
    description = models.TextField(
        blank=True,
        help_text="Description of what this variable is used for"
    )
    overrides_site = models.BooleanField(
        default=False,
        help_text="Whether this variable explicitly overrides a site-level variable"
    )
    
    # Access tracking
    last_accessed_at = models.DateTimeField(
        null=True, 
        blank=True,
        help_text="When this variable was last accessed"
    )
    access_count = models.PositiveIntegerField(
        default=0,
        help_text="Number of times this variable has been accessed"
    )
    
    # Versioning for secret rotation
    version = models.PositiveIntegerField(
        default=1,
        help_text="Version number for secret rotation tracking"
    )
    
    # Additional metadata
    metadata = models.JSONField(
        default=dict, 
        blank=True,
        help_text="Additional metadata (tags, rotation policy, etc.)"
    )
    
    class Meta:
        verbose_name = 'App Environment Variable'
        verbose_name_plural = 'App Environment Variables'
        unique_together = [['app_id', 'key']]  # Unique key per app
        indexes = [
            models.Index(fields=['app_id', 'key']),
            models.Index(fields=['app_id', 'variable_type']),
            models.Index(fields=['created_at']),
            models.Index(fields=['last_accessed_at']),
        ]
        ordering = ['app_id', 'key']
    
    def __str__(self) -> str:
        """String representation showing app, key and type."""
        override_indicator = " (overrides site)" if self.overrides_site else ""
        return f"App {self.app_id}: {self.key} ({self.get_variable_type_display()}){override_indicator}"
    
    def get_value(self) -> str:
        """
        Get decrypted value regardless of variable type.
        
        Returns:
            The actual value, decrypted if it's a secret
        """
        if self.variable_type == 'secret':
            return self.encrypted_value or ''
        return self.value
    
    def set_value(self, new_value: str) -> None:
        """
        Set value with appropriate encryption based on variable type.
        
        Args:
            new_value: The value to store
        """
        if self.variable_type == 'secret':
            self.encrypted_value = new_value
            self.value = ''  # Clear plaintext for security
        else:
            self.value = new_value
            self.encrypted_value = None
    
    def clean(self) -> None:
        """Validate the model."""
        super().clean()
        
        # Validate key format (alphanumeric, underscores, hyphens)
        import re
        if not re.match(r'^[A-Z0-9_-]+$', self.key):
            raise ValidationError({
                'key': 'Key must contain only uppercase letters, numbers, underscores, and hyphens'
            })
        
        # Ensure appropriate field is populated based on type
        if self.variable_type == 'secret':
            if not self.encrypted_value and not self.value:
                raise ValidationError({
                    'encrypted_value': 'Secret variables must have a value'
                })
        else:
            if not self.value:
                raise ValidationError({
                    'value': 'Configuration variables must have a value'
                })
    
    def save(self, *args, **kwargs) -> None:
        """Override save to handle encryption and validation."""
        self.full_clean()
        super().save(*args, **kwargs)
    
    def update_access_tracking(self) -> None:
        """Update access tracking fields."""
        self.last_accessed_at = timezone.now()
        self.access_count += 1
        self.save(update_fields=['last_accessed_at', 'access_count'])
    
    def rotate_secret(self, new_value: str, rotated_by: User, reason: str = '') -> 'SecretRotationHistory':
        """
        Rotate a secret value and create audit record.
        
        Args:
            new_value: New secret value
            rotated_by: User performing the rotation
            reason: Reason for rotation
            
        Returns:
            SecretRotationHistory record
            
        Raises:
            ValidationError: If variable is not a secret
        """
        if self.variable_type != 'secret':
            raise ValidationError("Only secret variables can be rotated")
        
        old_version = self.version
        self.version += 1
        self.set_value(new_value)
        self.modified_by = rotated_by
        self.save()
        
        # Create rotation history record
        return SecretRotationHistory.objects.create(
            variable_id=self.id,
            variable_scope='app',
            old_version=old_version,
            new_version=self.version,
            rotation_type='manual',
            rotated_by=rotated_by.id,
            reason=reason
        )


class EnvironmentVariablePermission(BaseModel):
    """
    Permissions for environment variables integrated with RBAC system.
    
    Defines who can read, write, delete, or rotate specific variables
    at both site and app levels.
    """
    
    SCOPE_CHOICES = [
        ('site', 'Site'),
        ('app', 'App'),
    ]
    
    PERMISSION_TYPE_CHOICES = [
        ('read', 'Read'),
        ('write', 'Write'), 
        ('delete', 'Delete'),
        ('rotate', 'Rotate'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    variable_id = models.UUIDField(
        db_index=True,
        help_text="ID of the environment variable"
    )
    variable_scope = models.CharField(
        max_length=10,
        choices=SCOPE_CHOICES,
        help_text="Whether this is a site or app level variable"
    )
    role_id = models.UUIDField(
        db_index=True,
        help_text="ID of the role that has this permission"
    )
    permission_type = models.CharField(
        max_length=20,
        choices=PERMISSION_TYPE_CHOICES,
        help_text="Type of permission granted"
    )
    
    class Meta:
        verbose_name = 'Environment Variable Permission'
        verbose_name_plural = 'Environment Variable Permissions'
        unique_together = [['variable_id', 'variable_scope', 'role_id', 'permission_type']]
        indexes = [
            models.Index(fields=['variable_id', 'variable_scope']),
            models.Index(fields=['role_id', 'permission_type']),
        ]
        ordering = ['variable_scope', 'permission_type']
    
    def __str__(self) -> str:
        """String representation showing permission details."""
        return f"{self.get_permission_type_display()} access to {self.variable_scope} variable {self.variable_id} for role {self.role_id}"


class SecretRotationHistory(BaseModel):
    """
    Audit trail for secret rotations.
    
    Tracks when secrets are rotated, by whom, and why for compliance
    and security monitoring.
    """
    
    SCOPE_CHOICES = [
        ('site', 'Site'),
        ('app', 'App'),
    ]
    
    ROTATION_TYPE_CHOICES = [
        ('manual', 'Manual'),
        ('scheduled', 'Scheduled'),
        ('emergency', 'Emergency'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    variable_id = models.UUIDField(
        db_index=True,
        help_text="ID of the rotated variable"
    )
    variable_scope = models.CharField(
        max_length=10,
        choices=SCOPE_CHOICES,
        help_text="Whether this was a site or app level variable"
    )
    old_version = models.PositiveIntegerField(
        help_text="Previous version number"
    )
    new_version = models.PositiveIntegerField(
        help_text="New version number after rotation"
    )
    rotation_type = models.CharField(
        max_length=20,
        choices=ROTATION_TYPE_CHOICES,
        help_text="Type of rotation performed"
    )
    rotated_at = models.DateTimeField(
        auto_now_add=True,
        help_text="When the rotation occurred"
    )
    rotated_by = models.UUIDField(
        help_text="ID of user who performed the rotation"
    )
    reason = models.TextField(
        blank=True,
        help_text="Reason for the rotation"
    )
    
    class Meta:
        verbose_name = 'Secret Rotation History'
        verbose_name_plural = 'Secret Rotation Histories'
        indexes = [
            models.Index(fields=['variable_id', 'rotated_at']),
            models.Index(fields=['rotated_by', 'rotated_at']),
            models.Index(fields=['rotation_type', 'rotated_at']),
        ]
        ordering = ['-rotated_at']
    
    def __str__(self) -> str:
        """String representation showing rotation details."""
        return f"{self.get_rotation_type_display()} rotation of {self.variable_scope} variable {self.variable_id} (v{self.old_version} → v{self.new_version})"


class VariableAccessLog(BaseModel):
    """
    Comprehensive audit logging for all variable access.
    
    Tracks every read, write, delete, and rotate operation for
    compliance and security monitoring.
    """
    
    SCOPE_CHOICES = [
        ('site', 'Site'),
        ('app', 'App'),
    ]
    
    ACCESS_TYPE_CHOICES = [
        ('read', 'Read'),
        ('write', 'Write'),
        ('delete', 'Delete'),
        ('rotate', 'Rotate'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    variable_id = models.UUIDField(
        db_index=True,
        help_text="ID of the accessed variable"
    )
    variable_scope = models.CharField(
        max_length=10,
        choices=SCOPE_CHOICES,
        help_text="Whether this was a site or app level variable"
    )
    variable_key = models.CharField(
        max_length=255, 
        db_index=True,
        help_text="Key name of the accessed variable"
    )
    user_id = models.UUIDField(
        db_index=True,
        help_text="ID of user who accessed the variable"
    )
    access_type = models.CharField(
        max_length=20,
        choices=ACCESS_TYPE_CHOICES,
        help_text="Type of access performed"
    )
    client_ip = models.GenericIPAddressField(
        help_text="IP address of the client"
    )
    user_agent = models.TextField(
        help_text="User agent string from the request"
    )
    access_time = models.DateTimeField(
        auto_now_add=True,
        help_text="When the access occurred"
    )
    response_status = models.PositiveIntegerField(
        help_text="HTTP response status code"
    )
    error_message = models.TextField(
        blank=True,
        help_text="Error message if access failed"
    )
    
    class Meta:
        verbose_name = 'Variable Access Log'
        verbose_name_plural = 'Variable Access Logs'
        indexes = [
            models.Index(fields=['variable_key', 'access_time']),
            models.Index(fields=['user_id', 'access_time']),
            models.Index(fields=['access_type', 'access_time']),
            models.Index(fields=['variable_id', 'access_time']),
        ]
        ordering = ['-access_time']
    
    def __str__(self) -> str:
        """String representation showing access details."""
        return f"{self.get_access_type_display()} access to {self.variable_key} by user {self.user_id} at {self.access_time}"