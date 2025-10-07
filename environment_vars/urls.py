"""
Environment Variables URL Configuration

Defines URL patterns for the environment variables API endpoints
with proper routing for site-level and app-level variables.
"""

from django.urls import path, include
from rest_framework.routers import DefaultRouter

from .views import (
    SiteEnvironmentVariableViewSet,
    AppEnvironmentVariableViewSet,
    EnvironmentVariablePermissionViewSet,
    SecretRotationHistoryViewSet,
    VariableAccessLogViewSet
)

# Create router for API endpoints
router = DefaultRouter()

# Site-level variables
router.register(
    r'site/variables', 
    SiteEnvironmentVariableViewSet, 
    basename='site-environment-variables'
)

# Permissions
router.register(
    r'permissions', 
    EnvironmentVariablePermissionViewSet, 
    basename='environment-variable-permissions'
)

# Audit and history
router.register(
    r'rotation-history', 
    SecretRotationHistoryViewSet, 
    basename='secret-rotation-history'
)

router.register(
    r'access-logs', 
    VariableAccessLogViewSet, 
    basename='variable-access-logs'
)

# App-level variables (nested under apps)
app_patterns = [
    path(
        'apps/<uuid:app_id>/variables/',
        include([
            path('', AppEnvironmentVariableViewSet.as_view({
                'get': 'list',
                'post': 'create'
            }), name='app-variables-list'),
            path('<uuid:pk>/', AppEnvironmentVariableViewSet.as_view({
                'get': 'retrieve',
                'put': 'update',
                'patch': 'partial_update',
                'delete': 'destroy'
            }), name='app-variables-detail'),
            path('<uuid:pk>/rotate/', AppEnvironmentVariableViewSet.as_view({
                'post': 'rotate'
            }), name='app-variables-rotate'),
            path('resolved/', AppEnvironmentVariableViewSet.as_view({
                'get': 'resolved'
            }), name='app-variables-resolved'),
            path('resolved/<str:key>/', AppEnvironmentVariableViewSet.as_view({
                'get': 'resolved_variable'
            }), name='app-variables-resolved-detail'),
        ])
    )
]

urlpatterns = [
    # Include router URLs
    path('', include(router.urls)),
    
    # Include app-level patterns
    path('', include(app_patterns)),
]

app_name = 'environment_vars'