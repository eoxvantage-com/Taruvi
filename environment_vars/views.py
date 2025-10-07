"""
Environment Variables API Views

Provides REST API endpoints for managing environment variables with
inheritance, caching, access control, and comprehensive audit logging.
"""

from typing import Dict, Any, Optional
import logging
from django.utils import timezone
from django.db import transaction
from rest_framework import viewsets, status, permissions
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.request import Request
from drf_spectacular.utils import extend_schema, OpenApiParameter
from drf_spectacular.types import OpenApiTypes

from core.decorators import api_rate_limit, burst_rate_limit
from .models import (
    SiteEnvironmentVariable,
    AppEnvironmentVariable,
    EnvironmentVariablePermission,
    SecretRotationHistory,
    VariableAccessLog
)
from .serializers import (
    SiteEnvironmentVariableSerializer,
    AppEnvironmentVariableSerializer,
    EnvironmentVariablePermissionSerializer,
    SecretRotationHistorySerializer,
    VariableAccessLogSerializer,
    VariableRotationSerializer,
    BulkRotationSerializer,
    ResolvedVariablesSerializer,
    VariableCreateUpdateSerializer
)
from .services import environment_service

logger = logging.getLogger(__name__)


class SiteEnvironmentVariableViewSet(viewsets.ModelViewSet):
    """
    ViewSet for managing site-level environment variables.
    
    Provides CRUD operations for site-level variables that cascade
    to all applications within the site.
    """
    
    serializer_class = SiteEnvironmentVariableSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        """Get site environment variables for current tenant."""
        return SiteEnvironmentVariable.objects.all().order_by('key')
    
    @api_rate_limit()
    def list(self, request: Request, *args, **kwargs) -> Response:
        """List all site environment variables."""
        return super().list(request, *args, **kwargs)
    
    @api_rate_limit()
    def retrieve(self, request: Request, *args, **kwargs) -> Response:
        """Retrieve a specific site environment variable."""
        return super().retrieve(request, *args, **kwargs)
    
    @burst_rate_limit()
    def create(self, request: Request, *args, **kwargs) -> Response:
        """Create a new site environment variable."""
        return super().create(request, *args, **kwargs)
    
    @burst_rate_limit()
    def update(self, request: Request, *args, **kwargs) -> Response:
        """Update a site environment variable."""
        return super().update(request, *args, **kwargs)
    
    @burst_rate_limit()
    def partial_update(self, request: Request, *args, **kwargs) -> Response:
        """Partially update a site environment variable."""
        return super().partial_update(request, *args, **kwargs)
    
    @burst_rate_limit()
    def destroy(self, request: Request, *args, **kwargs) -> Response:
        """Delete a site environment variable."""
        return super().destroy(request, *args, **kwargs)
    
    def perform_create(self, serializer) -> None:
        """Handle creation with audit logging."""
        instance = serializer.save(created_by=self.request.user)
        
        # Log the creation
        self._log_access(instance, 'write')
        
        logger.info(f"Created site variable {instance.key} by user {self.request.user.id}")
    
    def perform_update(self, serializer) -> None:
        """Handle updates with audit logging."""
        instance = serializer.save(modified_by=self.request.user)
        
        # Log the update
        self._log_access(instance, 'write')
        
        logger.info(f"Updated site variable {instance.key} by user {self.request.user.id}")
    
    def perform_destroy(self, instance) -> None:
        """Handle deletion with audit logging."""
        # Log the deletion before destroying
        self._log_access(instance, 'delete')
        
        logger.info(f"Deleted site variable {instance.key} by user {self.request.user.id}")
        super().perform_destroy(instance)
    
    @extend_schema(
        request=VariableRotationSerializer,
        responses={200: {'description': 'Secret rotated successfully'}},
        description="Rotate a secret variable"
    )
    @action(detail=True, methods=['post'])
    @burst_rate_limit()
    def rotate(self, request: Request, pk: str = None) -> Response:
        """Rotate a secret variable."""
        variable = self.get_object()
        
        if variable.variable_type != 'secret':
            return Response(
                {'error': 'Only secret variables can be rotated'}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        serializer = VariableRotationSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            rotation_history = variable.rotate_secret(
                new_value=serializer.validated_data['new_value'],
                rotated_by=request.user,
                reason=serializer.validated_data.get('reason', '')
            )
            
            # Log the rotation
            self._log_access(variable, 'rotate')
            
            return Response({
                'status': 'rotated',
                'new_version': variable.version,
                'rotation_id': rotation_history.id
            })
            
        except Exception as e:
            logger.error(f"Error rotating secret {variable.key}: {str(e)}")
            return Response(
                {'error': 'Failed to rotate secret'}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    @extend_schema(
        request=BulkRotationSerializer,
        responses={200: {'description': 'Bulk rotation initiated'}},
        description="Rotate multiple secrets at once"
    )
    @action(detail=False, methods=['post'])
    @burst_rate_limit()
    def bulk_rotate(self, request: Request) -> Response:
        """Rotate multiple secrets at once."""
        serializer = BulkRotationSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        variable_keys = serializer.validated_data['variable_keys']
        reason = serializer.validated_data.get('reason', '')
        
        results = []
        errors = []
        
        with transaction.atomic():
            for key in variable_keys:
                try:
                    variable = SiteEnvironmentVariable.objects.get(key=key)
                    if variable.variable_type != 'secret':
                        errors.append(f"{key}: Not a secret variable")
                        continue
                    
                    # Generate new secret (placeholder - implement actual secret generation)
                    import secrets
                    new_value = secrets.token_urlsafe(32)
                    
                    rotation_history = variable.rotate_secret(
                        new_value=new_value,
                        rotated_by=request.user,
                        reason=reason
                    )
                    
                    results.append({
                        'key': key,
                        'status': 'rotated',
                        'new_version': variable.version,
                        'rotation_id': rotation_history.id
                    })
                    
                    # Log the rotation
                    self._log_access(variable, 'rotate')
                    
                except SiteEnvironmentVariable.DoesNotExist:
                    errors.append(f"{key}: Variable not found")
                except Exception as e:
                    errors.append(f"{key}: {str(e)}")
        
        return Response({
            'status': 'completed',
            'rotated_count': len(results),
            'error_count': len(errors),
            'results': results,
            'errors': errors
        })
    
    def _log_access(self, variable, access_type: str) -> None:
        """Log variable access for audit trail."""
        try:
            VariableAccessLog.objects.create(
                variable_id=variable.id,
                variable_scope='site',
                variable_key=variable.key,
                user_id=self.request.user.id,
                access_type=access_type,
                client_ip=self._get_client_ip(),
                user_agent=self.request.META.get('HTTP_USER_AGENT', ''),
                response_status=200
            )
        except Exception as e:
            logger.error(f"Failed to log access: {str(e)}")
    
    def _get_client_ip(self) -> str:
        """Get client IP address from request."""
        x_forwarded_for = self.request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = self.request.META.get('REMOTE_ADDR')
        return ip or '127.0.0.1'


class AppEnvironmentVariableViewSet(viewsets.ModelViewSet):
    """
    ViewSet for managing app-level environment variables.
    
    Provides CRUD operations for app-level variables with inheritance
    from site-level variables and override capabilities.
    """
    
    serializer_class = AppEnvironmentVariableSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        """Get app environment variables for specific app."""
        app_id = self.kwargs.get('app_id')
        if app_id:
            return AppEnvironmentVariable.objects.filter(app_id=app_id).order_by('key')
        return AppEnvironmentVariable.objects.none()
    
    @api_rate_limit()
    def list(self, request: Request, *args, **kwargs) -> Response:
        """List all app environment variables."""
        return super().list(request, *args, **kwargs)
    
    @api_rate_limit()
    def retrieve(self, request: Request, *args, **kwargs) -> Response:
        """Retrieve a specific app environment variable."""
        return super().retrieve(request, *args, **kwargs)
    
    @burst_rate_limit()
    def create(self, request: Request, *args, **kwargs) -> Response:
        """Create a new app environment variable."""
        return super().create(request, *args, **kwargs)
    
    @burst_rate_limit()
    def update(self, request: Request, *args, **kwargs) -> Response:
        """Update an app environment variable."""
        return super().update(request, *args, **kwargs)
    
    @burst_rate_limit()
    def partial_update(self, request: Request, *args, **kwargs) -> Response:
        """Partially update an app environment variable."""
        return super().partial_update(request, *args, **kwargs)
    
    @burst_rate_limit()
    def destroy(self, request: Request, *args, **kwargs) -> Response:
        """Delete an app environment variable."""
        return super().destroy(request, *args, **kwargs)
    
    def perform_create(self, serializer) -> None:
        """Handle creation with audit logging."""
        app_id = self.kwargs.get('app_id')
        instance = serializer.save(
            app_id=app_id,
            created_by=self.request.user
        )
        
        # Log the creation
        self._log_access(instance, 'write')
        
        logger.info(f"Created app variable {instance.key} for app {app_id} by user {self.request.user.id}")
    
    def perform_update(self, serializer) -> None:
        """Handle updates with audit logging."""
        instance = serializer.save(modified_by=self.request.user)
        
        # Log the update
        self._log_access(instance, 'write')
        
        logger.info(f"Updated app variable {instance.key} by user {self.request.user.id}")
    
    def perform_destroy(self, instance) -> None:
        """Handle deletion with audit logging."""
        # Log the deletion before destroying
        self._log_access(instance, 'delete')
        
        logger.info(f"Deleted app variable {instance.key} by user {self.request.user.id}")
        super().perform_destroy(instance)
    
    @extend_schema(
        responses={200: ResolvedVariablesSerializer},
        description="Get resolved variables with inheritance applied"
    )
    @action(detail=False, methods=['get'])
    @api_rate_limit()
    def resolved(self, request: Request, *args, **kwargs) -> Response:
        """Get resolved variables with inheritance applied."""
        app_id = self.kwargs.get('app_id')
        if not app_id:
            return Response(
                {'error': 'app_id is required'}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            resolved_vars = environment_service.resolve_variables(
                app_id=app_id,
                user_id=str(request.user.id),
                request_ip=self._get_client_ip(),
                user_agent=request.META.get('HTTP_USER_AGENT', '')
            )
            
            return Response(resolved_vars)
            
        except Exception as e:
            logger.error(f"Error resolving variables for app {app_id}: {str(e)}")
            return Response(
                {'error': 'Failed to resolve variables'}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    @extend_schema(
        parameters=[
            OpenApiParameter(
                name='key',
                type=OpenApiTypes.STR,
                location=OpenApiParameter.PATH,
                description='Variable key to retrieve'
            )
        ],
        responses={200: {'description': 'Variable data with inheritance'}},
        description="Get a specific resolved variable"
    )
    @action(detail=False, methods=['get'], url_path='resolved/(?P<key>[^/.]+)')
    @api_rate_limit()
    def resolved_variable(self, request: Request, key: str = None, *args, **kwargs) -> Response:
        """Get a specific resolved variable."""
        app_id = self.kwargs.get('app_id')
        if not app_id:
            return Response(
                {'error': 'app_id is required'}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            variable_data = environment_service.get_variable(
                key=key,
                app_id=app_id,
                user_id=str(request.user.id),
                request_ip=self._get_client_ip(),
                user_agent=request.META.get('HTTP_USER_AGENT', '')
            )
            
            if variable_data:
                return Response(variable_data)
            else:
                return Response(
                    {'error': 'Variable not found or access denied'}, 
                    status=status.HTTP_404_NOT_FOUND
                )
                
        except Exception as e:
            logger.error(f"Error getting variable {key} for app {app_id}: {str(e)}")
            return Response(
                {'error': 'Failed to get variable'}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    @extend_schema(
        request=VariableRotationSerializer,
        responses={200: {'description': 'Secret rotated successfully'}},
        description="Rotate a secret variable"
    )
    @action(detail=True, methods=['post'])
    @burst_rate_limit()
    def rotate(self, request: Request, pk: str = None) -> Response:
        """Rotate a secret variable."""
        variable = self.get_object()
        
        if variable.variable_type != 'secret':
            return Response(
                {'error': 'Only secret variables can be rotated'}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        serializer = VariableRotationSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            rotation_history = variable.rotate_secret(
                new_value=serializer.validated_data['new_value'],
                rotated_by=request.user,
                reason=serializer.validated_data.get('reason', '')
            )
            
            # Log the rotation
            self._log_access(variable, 'rotate')
            
            return Response({
                'status': 'rotated',
                'new_version': variable.version,
                'rotation_id': rotation_history.id
            })
            
        except Exception as e:
            logger.error(f"Error rotating secret {variable.key}: {str(e)}")
            return Response(
                {'error': 'Failed to rotate secret'}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    def _log_access(self, variable, access_type: str) -> None:
        """Log variable access for audit trail."""
        try:
            VariableAccessLog.objects.create(
                variable_id=variable.id,
                variable_scope='app',
                variable_key=variable.key,
                user_id=self.request.user.id,
                access_type=access_type,
                client_ip=self._get_client_ip(),
                user_agent=self.request.META.get('HTTP_USER_AGENT', ''),
                response_status=200
            )
        except Exception as e:
            logger.error(f"Failed to log access: {str(e)}")
    
    def _get_client_ip(self) -> str:
        """Get client IP address from request."""
        x_forwarded_for = self.request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = self.request.META.get('REMOTE_ADDR')
        return ip or '127.0.0.1'


class EnvironmentVariablePermissionViewSet(viewsets.ModelViewSet):
    """ViewSet for managing environment variable permissions."""
    
    serializer_class = EnvironmentVariablePermissionSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        """Get permissions for current tenant."""
        return EnvironmentVariablePermission.objects.all().order_by('variable_scope', 'permission_type')


class SecretRotationHistoryViewSet(viewsets.ReadOnlyModelViewSet):
    """ViewSet for viewing secret rotation history."""
    
    serializer_class = SecretRotationHistorySerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        """Get rotation history for current tenant."""
        return SecretRotationHistory.objects.all().order_by('-rotated_at')


class VariableAccessLogViewSet(viewsets.ReadOnlyModelViewSet):
    """ViewSet for viewing variable access logs."""
    
    serializer_class = VariableAccessLogSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        """Get access logs for current tenant."""
        return VariableAccessLog.objects.all().order_by('-access_time')
    
    @extend_schema(
        parameters=[
            OpenApiParameter(
                name='variable_key',
                type=OpenApiTypes.STR,
                location=OpenApiParameter.QUERY,
                description='Filter by variable key'
            ),
            OpenApiParameter(
                name='access_type',
                type=OpenApiTypes.STR,
                location=OpenApiParameter.QUERY,
                description='Filter by access type'
            ),
            OpenApiParameter(
                name='user_id',
                type=OpenApiTypes.STR,
                location=OpenApiParameter.QUERY,
                description='Filter by user ID'
            ),
        ],
        description="Get audit logs with optional filtering"
    )
    @action(detail=False, methods=['get'])
    @api_rate_limit()
    def audit(self, request: Request) -> Response:
        """Get audit logs with filtering."""
        queryset = self.get_queryset()
        
        # Apply filters
        variable_key = request.query_params.get('variable_key')
        if variable_key:
            queryset = queryset.filter(variable_key=variable_key)
        
        access_type = request.query_params.get('access_type')
        if access_type:
            queryset = queryset.filter(access_type=access_type)
        
        user_id = request.query_params.get('user_id')
        if user_id:
            queryset = queryset.filter(user_id=user_id)
        
        # Paginate results
        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)
        
        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)