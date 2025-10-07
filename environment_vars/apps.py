from django.apps import AppConfig


class EnvironmentVarsConfig(AppConfig):
    """
    Django app configuration for Environment Variables.
    
    This app provides hierarchical environment variables and secrets management
    with site-to-app inheritance, encryption, and comprehensive audit logging.
    """
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'environment_vars'
    verbose_name = 'Environment Variables'
    
    def ready(self) -> None:
        """Initialize app when Django starts."""
        # Import signals to ensure they're registered
        try:
            from . import signals  # noqa: F401
        except ImportError:
            pass