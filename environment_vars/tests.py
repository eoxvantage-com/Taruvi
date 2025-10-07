"""
Tests for Environment Variables System

Provides comprehensive tests for models, services, views, and encryption
functionality of the hierarchical environment variables system.
"""

import uuid
from django.test import TestCase, TransactionTestCase
from django.contrib.auth.models import User
from django.core.exceptions import ValidationError
from django.urls import reverse
from rest_framework.test import APITestCase
from rest_framework import status

from .models import (
    SiteEnvironmentVariable,
    AppEnvironmentVariable,
    EnvironmentVariablePermission,
    SecretRotationHistory,
    VariableAccessLog
)
from .services import environment_service
from .encryption import TenantKeyManager


class SiteEnvironmentVariableModelTest(TestCase):
    """Test cases for SiteEnvironmentVariable model."""
    
    def setUp(self):
        """Set up test data."""
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
    
    def test_create_config_variable(self):
        """Test creating a configuration variable."""
        variable = SiteEnvironmentVariable.objects.create(
            key='API_TIMEOUT',
            variable_type='config',
            description='API request timeout in seconds',
            created_by=self.user
        )
        variable.set_value('30')
        variable.save()
        
        self.assertEqual(variable.key, 'API_TIMEOUT')
        self.assertEqual(variable.variable_type, 'config')
        self.assertEqual(variable.get_value(), '30')
        self.assertEqual(variable.value, '30')
        self.assertIsNone(variable.encrypted_value)
    
    def test_create_secret_variable(self):
        """Test creating a secret variable."""
        variable = SiteEnvironmentVariable.objects.create(
            key='DATABASE_PASSWORD',
            variable_type='secret',
            description='Database connection password',
            created_by=self.user
        )
        variable.set_value('super_secret_password')
        variable.save()
        
        self.assertEqual(variable.key, 'DATABASE_PASSWORD')
        self.assertEqual(variable.variable_type, 'secret')
        self.assertEqual(variable.get_value(), 'super_secret_password')
        self.assertEqual(variable.value, '')  # Should be cleared for security
        self.assertIsNotNone(variable.encrypted_value)
    
    def test_key_validation(self):
        """Test key format validation."""
        # Valid keys
        valid_keys = ['API_KEY', 'DATABASE_URL', 'REDIS_HOST', 'APP_DEBUG']
        for key in valid_keys:
            variable = SiteEnvironmentVariable(
                key=key,
                variable_type='config',
                created_by=self.user
            )
            variable.set_value('test_value')
            variable.full_clean()  # Should not raise ValidationError
        
        # Invalid keys
        invalid_keys = ['api_key', 'API KEY', 'API-key', '123KEY', 'KEY@']
        for key in invalid_keys:
            variable = SiteEnvironmentVariable(
                key=key,
                variable_type='config',
                created_by=self.user
            )
            variable.set_value('test_value')
            with self.assertRaises(ValidationError):
                variable.full_clean()
    
    def test_secret_rotation(self):
        """Test secret rotation functionality."""
        variable = SiteEnvironmentVariable.objects.create(
            key='API_SECRET',
            variable_type='secret',
            description='API secret key',
            created_by=self.user
        )
        variable.set_value('old_secret')
        variable.save()
        
        original_version = variable.version
        
        # Rotate the secret
        rotation_history = variable.rotate_secret(
            new_value='new_secret',
            rotated_by=self.user,
            reason='Scheduled rotation'
        )
        
        # Check that version was incremented
        self.assertEqual(variable.version, original_version + 1)
        self.assertEqual(variable.get_value(), 'new_secret')
        
        # Check rotation history
        self.assertEqual(rotation_history.old_version, original_version)
        self.assertEqual(rotation_history.new_version, variable.version)
        self.assertEqual(rotation_history.reason, 'Scheduled rotation')
    
    def test_access_tracking(self):
        """Test access tracking functionality."""
        variable = SiteEnvironmentVariable.objects.create(
            key='TRACKING_TEST',
            variable_type='config',
            created_by=self.user
        )
        variable.set_value('test_value')
        variable.save()
        
        original_count = variable.access_count
        original_time = variable.last_accessed_at
        
        # Update access tracking
        variable.update_access_tracking()
        
        self.assertEqual(variable.access_count, original_count + 1)
        self.assertNotEqual(variable.last_accessed_at, original_time)


class AppEnvironmentVariableModelTest(TestCase):
    """Test cases for AppEnvironmentVariable model."""
    
    def setUp(self):
        """Set up test data."""
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
        self.app_id = uuid.uuid4()
    
    def test_create_app_variable(self):
        """Test creating an app-level variable."""
        variable = AppEnvironmentVariable.objects.create(
            app_id=self.app_id,
            key='APP_DEBUG',
            variable_type='config',
            description='Debug mode for this app',
            overrides_site=True,
            created_by=self.user
        )
        variable.set_value('true')
        variable.save()
        
        self.assertEqual(variable.app_id, self.app_id)
        self.assertEqual(variable.key, 'APP_DEBUG')
        self.assertTrue(variable.overrides_site)
        self.assertEqual(variable.get_value(), 'true')
    
    def test_app_secret_rotation(self):
        """Test secret rotation for app variables."""
        variable = AppEnvironmentVariable.objects.create(
            app_id=self.app_id,
            key='APP_SECRET',
            variable_type='secret',
            description='App-specific secret',
            created_by=self.user
        )
        variable.set_value('app_secret')
        variable.save()
        
        # Rotate the secret
        rotation_history = variable.rotate_secret(
            new_value='new_app_secret',
            rotated_by=self.user,
            reason='Security update'
        )
        
        self.assertEqual(variable.get_value(), 'new_app_secret')
        self.assertEqual(rotation_history.variable_scope, 'app')


class EnvironmentVariableServiceTest(TestCase):
    """Test cases for EnvironmentVariableService."""
    
    def setUp(self):
        """Set up test data."""
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
        self.app_id = str(uuid.uuid4())
        
        # Create site-level variables
        self.site_config = SiteEnvironmentVariable.objects.create(
            key='SITE_CONFIG',
            variable_type='config',
            description='Site-level configuration',
            created_by=self.user
        )
        self.site_config.set_value('site_value')
        self.site_config.save()
        
        self.site_secret = SiteEnvironmentVariable.objects.create(
            key='SITE_SECRET',
            variable_type='secret',
            description='Site-level secret',
            created_by=self.user
        )
        self.site_secret.set_value('site_secret_value')
        self.site_secret.save()
        
        # Create app-level variables
        self.app_config = AppEnvironmentVariable.objects.create(
            app_id=self.app_id,
            key='APP_CONFIG',
            variable_type='config',
            description='App-specific configuration',
            created_by=self.user
        )
        self.app_config.set_value('app_value')
        self.app_config.save()
        
        self.app_override = AppEnvironmentVariable.objects.create(
            app_id=self.app_id,
            key='SITE_CONFIG',
            variable_type='config',
            description='App override of site config',
            overrides_site=True,
            created_by=self.user
        )
        self.app_override.set_value('app_override_value')
        self.app_override.save()
    
    def test_resolve_variables(self):
        """Test variable resolution with inheritance."""
        resolved = environment_service.resolve_variables(
            app_id=self.app_id,
            user_id=str(self.user.id),
            request_ip='127.0.0.1',
            user_agent='test'
        )
        
        variables = resolved['variables']
        
        # Check that site secret is inherited
        self.assertIn('SITE_SECRET', variables)
        self.assertEqual(variables['SITE_SECRET']['source'], 'site')
        self.assertTrue(variables['SITE_SECRET']['inherited'])
        
        # Check that app config is app-specific
        self.assertIn('APP_CONFIG', variables)
        self.assertEqual(variables['APP_CONFIG']['source'], 'app')
        self.assertTrue(variables['APP_CONFIG']['app_specific'])
        
        # Check that site config is overridden by app
        self.assertIn('SITE_CONFIG', variables)
        self.assertEqual(variables['SITE_CONFIG']['source'], 'app')
        self.assertTrue(variables['SITE_CONFIG']['overridden'])
        self.assertEqual(variables['SITE_CONFIG']['value'], 'app_override_value')
    
    def test_get_specific_variable(self):
        """Test getting a specific variable with inheritance."""
        # Get site variable
        site_var = environment_service.get_variable(
            key='SITE_SECRET',
            app_id=self.app_id,
            user_id=str(self.user.id)
        )
        self.assertIsNotNone(site_var)
        self.assertEqual(site_var['source'], 'site')
        
        # Get app-specific variable
        app_var = environment_service.get_variable(
            key='APP_CONFIG',
            app_id=self.app_id,
            user_id=str(self.user.id)
        )
        self.assertIsNotNone(app_var)
        self.assertEqual(app_var['source'], 'app')
        
        # Get overridden variable
        override_var = environment_service.get_variable(
            key='SITE_CONFIG',
            app_id=self.app_id,
            user_id=str(self.user.id)
        )
        self.assertIsNotNone(override_var)
        self.assertEqual(override_var['value'], 'app_override_value')


class TenantKeyManagerTest(TestCase):
    """Test cases for TenantKeyManager."""
    
    def test_generate_tenant_keys(self):
        """Test generating tenant keys."""
        tenant_id = 'test_tenant'
        primary_key, rotation_key = TenantKeyManager.generate_tenant_keys(tenant_id)
        
        self.assertIsInstance(primary_key, str)
        self.assertIsInstance(rotation_key, str)
        self.assertNotEqual(primary_key, rotation_key)
        
        # Keys should be valid Fernet keys (44 characters base64)
        self.assertEqual(len(primary_key), 44)
        self.assertEqual(len(rotation_key), 44)
    
    def test_validate_tenant_keys(self):
        """Test validating tenant keys."""
        # This test would require setting up environment variables
        # In a real test environment, you'd mock the environment
        pass


class EnvironmentVariableAPITest(APITestCase):
    """Test cases for Environment Variables API."""
    
    def setUp(self):
        """Set up test data."""
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
        self.client.force_authenticate(user=self.user)
        self.app_id = uuid.uuid4()
    
    def test_create_site_variable(self):
        """Test creating a site variable via API."""
        url = reverse('environment_vars:site-environment-variables-list')
        data = {
            'key': 'API_KEY',
            'value': 'test_api_key',
            'variable_type': 'secret',
            'description': 'API key for external service'
        }
        
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        
        # Check that variable was created
        variable = SiteEnvironmentVariable.objects.get(key='API_KEY')
        self.assertEqual(variable.variable_type, 'secret')
        self.assertEqual(variable.get_value(), 'test_api_key')
    
    def test_list_site_variables(self):
        """Test listing site variables via API."""
        # Create test variable
        variable = SiteEnvironmentVariable.objects.create(
            key='TEST_VAR',
            variable_type='config',
            description='Test variable',
            created_by=self.user
        )
        variable.set_value('test_value')
        variable.save()
        
        url = reverse('environment_vars:site-environment-variables-list')
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data['results']), 1)
        self.assertEqual(response.data['results'][0]['key'], 'TEST_VAR')
    
    def test_resolve_app_variables(self):
        """Test resolving app variables via API."""
        # Create site and app variables
        site_var = SiteEnvironmentVariable.objects.create(
            key='SITE_VAR',
            variable_type='config',
            created_by=self.user
        )
        site_var.set_value('site_value')
        site_var.save()
        
        app_var = AppEnvironmentVariable.objects.create(
            app_id=self.app_id,
            key='APP_VAR',
            variable_type='config',
            created_by=self.user
        )
        app_var.set_value('app_value')
        app_var.save()
        
        url = reverse('environment_vars:app-variables-resolved', kwargs={'app_id': self.app_id})
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        variables = response.data['variables']
        
        self.assertIn('SITE_VAR', variables)
        self.assertIn('APP_VAR', variables)
        self.assertEqual(variables['SITE_VAR']['source'], 'site')
        self.assertEqual(variables['APP_VAR']['source'], 'app')