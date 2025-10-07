"""
Management command for setting up encryption keys for environment variables.

Provides utilities for generating, validating, and rotating encryption keys
for tenant-specific environment variable encryption.
"""

from typing import Optional
from django.core.management.base import BaseCommand, CommandError
from django.conf import settings
from core.models import Site
from environment_vars.encryption import TenantKeyManager


class Command(BaseCommand):
    """
    Management command for encryption key operations.
    
    Supports generating new keys, validating existing keys, and rotating keys
    for specific tenants or all tenants.
    """
    
    help = 'Manage encryption keys for environment variables'
    
    def add_arguments(self, parser):
        """Add command line arguments."""
        parser.add_argument(
            '--action',
            type=str,
            choices=['generate', 'validate', 'rotate', 'list'],
            default='generate',
            help='Action to perform (default: generate)'
        )
        
        parser.add_argument(
            '--tenant-id',
            type=str,
            help='Specific tenant ID to operate on (if not provided, operates on all tenants)'
        )
        
        parser.add_argument(
            '--output-format',
            type=str,
            choices=['env', 'json', 'yaml'],
            default='env',
            help='Output format for generated keys (default: env)'
        )
        
        parser.add_argument(
            '--force',
            action='store_true',
            help='Force operation even if keys already exist'
        )
    
    def handle(self, *args, **options):
        """Handle the command execution."""
        action = options['action']
        tenant_id = options.get('tenant_id')
        output_format = options['output_format']
        force = options['force']
        
        try:
            if action == 'generate':
                self.generate_keys(tenant_id, output_format, force)
            elif action == 'validate':
                self.validate_keys(tenant_id)
            elif action == 'rotate':
                self.rotate_keys(tenant_id, force)
            elif action == 'list':
                self.list_tenants()
                
        except Exception as e:
            raise CommandError(f'Command failed: {str(e)}')
    
    def generate_keys(self, tenant_id: Optional[str], output_format: str, force: bool):
        """Generate encryption keys for tenant(s)."""
        if tenant_id:
            tenants = [tenant_id]
        else:
            # Get all tenant IDs from Site model
            tenants = [str(site.id) for site in Site.objects.all()]
            if not tenants:
                self.stdout.write(
                    self.style.WARNING('No tenants found. Creating keys for default tenant.')
                )
                tenants = ['default']
        
        for tid in tenants:
            self.stdout.write(f'Generating keys for tenant: {tid}')
            
            # Check if keys already exist
            existing_keys = TenantKeyManager.get_tenant_keys(tid)
            if existing_keys and not force:
                self.stdout.write(
                    self.style.WARNING(f'Keys already exist for tenant {tid}. Use --force to overwrite.')
                )
                continue
            
            # Generate new keys
            primary_key, rotation_key = TenantKeyManager.generate_tenant_keys(tid)
            
            # Output keys in requested format
            if output_format == 'env':
                self.stdout.write(f'# Environment variables for tenant {tid}')
                self.stdout.write(f'TENANT_{tid}_FERNET_KEY_1={primary_key}')
                self.stdout.write(f'TENANT_{tid}_FERNET_KEY_2={rotation_key}')
                self.stdout.write('')
            elif output_format == 'json':
                import json
                keys_data = {
                    'tenant_id': tid,
                    'primary_key': primary_key,
                    'rotation_key': rotation_key
                }
                self.stdout.write(json.dumps(keys_data, indent=2))
            elif output_format == 'yaml':
                self.stdout.write(f'tenant_{tid}:')
                self.stdout.write(f'  primary_key: {primary_key}')
                self.stdout.write(f'  rotation_key: {rotation_key}')
        
        self.stdout.write(
            self.style.SUCCESS(f'Successfully generated keys for {len(tenants)} tenant(s)')
        )
    
    def validate_keys(self, tenant_id: Optional[str]):
        """Validate encryption keys for tenant(s)."""
        if tenant_id:
            tenants = [tenant_id]
        else:
            # Get all tenant IDs from Site model
            tenants = [str(site.id) for site in Site.objects.all()]
            if not tenants:
                tenants = ['default']
        
        valid_count = 0
        invalid_count = 0
        
        for tid in tenants:
            self.stdout.write(f'Validating keys for tenant: {tid}')
            
            if TenantKeyManager.validate_tenant_keys(tid):
                self.stdout.write(
                    self.style.SUCCESS(f'✓ Keys are valid for tenant {tid}')
                )
                valid_count += 1
            else:
                self.stdout.write(
                    self.style.ERROR(f'✗ Keys are invalid or missing for tenant {tid}')
                )
                invalid_count += 1
        
        self.stdout.write('')
        self.stdout.write(f'Validation complete: {valid_count} valid, {invalid_count} invalid')
        
        if invalid_count > 0:
            raise CommandError(f'{invalid_count} tenant(s) have invalid or missing keys')
    
    def rotate_keys(self, tenant_id: Optional[str], force: bool):
        """Rotate encryption keys for tenant(s)."""
        if tenant_id:
            tenants = [tenant_id]
        else:
            # Get all tenant IDs from Site model
            tenants = [str(site.id) for site in Site.objects.all()]
            if not tenants:
                tenants = ['default']
        
        if not force:
            self.stdout.write(
                self.style.WARNING(
                    'Key rotation will invalidate existing encrypted data unless '
                    'you update environment variables. Use --force to proceed.'
                )
            )
            return
        
        for tid in tenants:
            self.stdout.write(f'Rotating keys for tenant: {tid}')
            
            try:
                new_primary_key = TenantKeyManager.rotate_tenant_keys(tid)
                self.stdout.write(
                    self.style.SUCCESS(f'✓ Keys rotated for tenant {tid}')
                )
                self.stdout.write(f'New primary key: {new_primary_key}')
                self.stdout.write(
                    self.style.WARNING(
                        f'Update TENANT_{tid}_FERNET_KEY_1 environment variable with the new key'
                    )
                )
            except Exception as e:
                self.stdout.write(
                    self.style.ERROR(f'✗ Failed to rotate keys for tenant {tid}: {str(e)}')
                )
        
        self.stdout.write(
            self.style.SUCCESS(f'Key rotation completed for {len(tenants)} tenant(s)')
        )
    
    def list_tenants(self):
        """List all tenants and their key status."""
        sites = Site.objects.all()
        
        if not sites:
            self.stdout.write(self.style.WARNING('No tenants found'))
            return
        
        self.stdout.write('Tenant Key Status:')
        self.stdout.write('-' * 50)
        
        for site in sites:
            tenant_id = str(site.id)
            has_keys = bool(TenantKeyManager.get_tenant_keys(tenant_id))
            is_valid = TenantKeyManager.validate_tenant_keys(tenant_id) if has_keys else False
            
            status = '✓ Valid' if is_valid else ('✗ Invalid' if has_keys else '- No keys')
            style = self.style.SUCCESS if is_valid else (
                self.style.ERROR if has_keys else self.style.WARNING
            )
            
            self.stdout.write(f'{site.name} ({tenant_id}): {style(status)}')
        
        self.stdout.write('')
        self.stdout.write(f'Total tenants: {sites.count()}')