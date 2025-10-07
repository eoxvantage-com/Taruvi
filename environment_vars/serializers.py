"""
Environment Variables Serializers

Provides DRF serializers for environment variables with proper validation,
field handling, and security considerations for encrypted fields.
"""

from typing import Dict, Any
from rest_framework import serializers
from django.contrib.auth.models import User

from .models import (
    SiteEnvironmentVariable,
    AppEnvironmentVariable,
    EnvironmentVariablePermission,
    SecretRotationHistory,
    VariableAccessLog
)


class SiteEnvironmentVariableSerializer(serializers.ModelSerializer):
    """
    Serializer for site-level environment variables.
    
    Handles conditional encryption and provides secure field access
    based on variable type.
    """
    
    # Read-only computed fields
    is_encrypted = serializers.SerializerMethodField()
    
    class Meta:
        model = SiteEnvironmentVariable
        fields = [
            'id', 'key', 'value', 'variable_type', 'description',
            'is_encrypted', 'created_at', 'updated_at', 'created_by',
            'last_accessed_at', 'access_count', 'version', 'metadata'
        ]
        read_only_fields = [
            'id', 'created_at', 'updated_at', 'created_by', 'modified_by',
            'last_accessed_at', 'access_count', 'version', 'is_encrypted'
        ]
        extra_kwargs = {
            'value': {'write_only': True},  # Don't expose raw values in responses
        }
    
    def get_is_encrypted(self, obj: SiteEnvironmentVariable) -> bool:
        """Return whether this variable is encrypted."""
        return obj.variable_type == 'secret'
    
    def validate_key(self, value: str) -> str:
        """Validate variable key format."""
        import re
        if not re.match(r'^[A-Z0-9_-]+$', value):
            raise serializers.ValidationError(
                'Key must contain only uppercase letters, numbers, underscores, and hyphens'
            )
        return value
    
    def validate(self, attrs: Dict[str, Any]) -> Dict[str, Any]:
        """Validate the entire object."""
        variable_type = attrs.get('variable_type', 'config')
        value = attrs.get('value', '')
        
        if not value:
            raise serializers.ValidationError({
                'value': 'Value is required'
            })
        
        return attrs
    
    def create(self, validated_data: Dict[str, Any]) -> SiteEnvironmentVariable:
        """Create a new site environment variable."""
        value = validated_data.pop('value')
        instance = SiteEnvironmentVariable.objects.create(**validated_data)
        instance.set_value(value)
        instance.save()
        return instance
    
    def update(self, instance: SiteEnvironmentVariable, validated_data: Dict[str, Any]) -> SiteEnvironmentVariable:
        """Update an existing site environment variable."""
        value = validated_data.pop('value', None)
        
        # Update other fields
        for attr, value_attr in validated_data.items():
            setattr(instance, attr, value_attr)
        
        # Update value if provided
        if value is not None:
            instance.set_value(value)
        
        instance.save()
        return instance
    
    def to_representation(self, instance: SiteEnvironmentVariable) -> Dict[str, Any]:
        """Customize the output representation."""
        data = super().to_representation(instance)
        
        # Replace value with actual decrypted value for response
        data['value'] = instance.get_value()
        
        # Add computed fields
        data['source'] = 'site'
        
        return data


class AppEnvironmentVariableSerializer(serializers.ModelSerializer):
    """
    Serializer for app-level environment variables.
    
    Handles conditional encryption and inheritance logic.
    """
    
    # Read-only computed fields
    is_encrypted = serializers.SerializerMethodField()
    
    class Meta:
        model = AppEnvironmentVariable
        fields = [
            'id', 'app_id', 'key', 'value', 'variable_type', 'description',
            'overrides_site', 'is_encrypted', 'created_at', 'updated_at',
            'created_by', 'last_accessed_at', 'access_count', 'version', 'metadata'
        ]
        read_only_fields = [
            'id', 'created_at', 'updated_at', 'created_by', 'modified_by',
            'last_accessed_at', 'access_count', 'version', 'is_encrypted'
        ]
        extra_kwargs = {
            'value': {'write_only': True},  # Don't expose raw values in responses
        }
    
    def get_is_encrypted(self, obj: AppEnvironmentVariable) -> bool:
        """Return whether this variable is encrypted."""
        return obj.variable_type == 'secret'
    
    def validate_key(self, value: str) -> str:
        """Validate variable key format."""
        import re
        if not re.match(r'^[A-Z0-9_-]+$', value):
            raise serializers.ValidationError(
                'Key must contain only uppercase letters, numbers, underscores, and hyphens'
            )
        return value
    
    def validate_app_id(self, value: str) -> str:
        """Validate app_id format."""
        try:
            import uuid
            uuid.UUID(value)
        except ValueError:
            raise serializers.ValidationError('app_id must be a valid UUID')
        return value
    
    def validate(self, attrs: Dict[str, Any]) -> Dict[str, Any]:
        """Validate the entire object."""
        variable_type = attrs.get('variable_type', 'config')
        value = attrs.get('value', '')
        
        if not value:
            raise serializers.ValidationError({
                'value': 'Value is required'
            })
        
        return attrs
    
    def create(self, validated_data: Dict[str, Any]) -> AppEnvironmentVariable:
        """Create a new app environment variable."""
        value = validated_data.pop('value')
        instance = AppEnvironmentVariable.objects.create(**validated_data)
        instance.set_value(value)
        instance.save()
        return instance
    
    def update(self, instance: AppEnvironmentVariable, validated_data: Dict[str, Any]) -> AppEnvironmentVariable:
        """Update an existing app environment variable."""
        value = validated_data.pop('value', None)
        
        # Update other fields
        for attr, value_attr in validated_data.items():
            setattr(instance, attr, value_attr)
        
        # Update value if provided
        if value is not None:
            instance.set_value(value)
        
        instance.save()
        return instance
    
    def to_representation(self, instance: AppEnvironmentVariable) -> Dict[str, Any]:
        """Customize the output representation."""
        data = super().to_representation(instance)
        
        # Replace value with actual decrypted value for response
        data['value'] = instance.get_value()
        
        # Add computed fields
        data['source'] = 'app'
        
        return data


class EnvironmentVariablePermissionSerializer(serializers.ModelSerializer):
    """Serializer for environment variable permissions."""
    
    class Meta:
        model = EnvironmentVariablePermission
        fields = [
            'id', 'variable_id', 'variable_scope', 'role_id', 'permission_type',
            'created_at', 'created_by'
        ]
        read_only_fields = ['id', 'created_at', 'created_by']
    
    def validate_variable_id(self, value: str) -> str:
        """Validate variable_id format."""
        try:
            import uuid
            uuid.UUID(value)
        except ValueError:
            raise serializers.ValidationError('variable_id must be a valid UUID')
        return value
    
    def validate_role_id(self, value: str) -> str:
        """Validate role_id format."""
        try:
            import uuid
            uuid.UUID(value)
        except ValueError:
            raise serializers.ValidationError('role_id must be a valid UUID')
        return value


class SecretRotationHistorySerializer(serializers.ModelSerializer):
    """Serializer for secret rotation history."""
    
    class Meta:
        model = SecretRotationHistory
        fields = [
            'id', 'variable_id', 'variable_scope', 'old_version', 'new_version',
            'rotation_type', 'rotated_at', 'rotated_by', 'reason'
        ]
        read_only_fields = ['id', 'rotated_at']


class VariableAccessLogSerializer(serializers.ModelSerializer):
    """Serializer for variable access logs."""
    
    class Meta:
        model = VariableAccessLog
        fields = [
            'id', 'variable_id', 'variable_scope', 'variable_key', 'user_id',
            'access_type', 'client_ip', 'user_agent', 'access_time',
            'response_status', 'error_message'
        ]
        read_only_fields = ['id', 'access_time']


class VariableRotationSerializer(serializers.Serializer):
    """Serializer for secret rotation requests."""
    
    new_value = serializers.CharField(
        max_length=10000,
        help_text="New secret value"
    )
    reason = serializers.CharField(
        max_length=1000,
        required=False,
        allow_blank=True,
        help_text="Reason for rotation"
    )
    rotation_type = serializers.ChoiceField(
        choices=[
            ('manual', 'Manual'),
            ('scheduled', 'Scheduled'),
            ('emergency', 'Emergency'),
        ],
        default='manual',
        help_text="Type of rotation"
    )


class BulkRotationSerializer(serializers.Serializer):
    """Serializer for bulk secret rotation requests."""
    
    variable_keys = serializers.ListField(
        child=serializers.CharField(max_length=255),
        help_text="List of variable keys to rotate"
    )
    reason = serializers.CharField(
        max_length=1000,
        required=False,
        allow_blank=True,
        help_text="Reason for bulk rotation"
    )
    rotation_type = serializers.ChoiceField(
        choices=[
            ('manual', 'Manual'),
            ('scheduled', 'Scheduled'),
            ('emergency', 'Emergency'),
        ],
        default='manual',
        help_text="Type of rotation"
    )


class ResolvedVariablesSerializer(serializers.Serializer):
    """Serializer for resolved variables response."""
    
    variables = serializers.DictField(
        help_text="Resolved variables with inheritance applied"
    )
    metadata = serializers.DictField(
        help_text="Metadata about the resolution process"
    )


class VariableCreateUpdateSerializer(serializers.Serializer):
    """Serializer for creating/updating variables via unified API."""
    
    key = serializers.CharField(
        max_length=255,
        help_text="Variable key name"
    )
    value = serializers.CharField(
        max_length=10000,
        help_text="Variable value"
    )
    variable_type = serializers.ChoiceField(
        choices=[('config', 'Configuration'), ('secret', 'Secret')],
        default='config',
        help_text="Type of variable"
    )
    description = serializers.CharField(
        max_length=1000,
        required=False,
        allow_blank=True,
        help_text="Variable description"
    )
    overrides_site = serializers.BooleanField(
        default=False,
        help_text="Whether app variable overrides site variable (app-level only)"
    )
    metadata = serializers.JSONField(
        required=False,
        default=dict,
        help_text="Additional metadata"
    )
    
    def validate_key(self, value: str) -> str:
        """Validate variable key format."""
        import re
        if not re.match(r'^[A-Z0-9_-]+$', value):
            raise serializers.ValidationError(
                'Key must contain only uppercase letters, numbers, underscores, and hyphens'
            )
        return value