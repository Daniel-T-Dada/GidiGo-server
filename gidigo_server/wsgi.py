"""
WSGI config for gidigo_server project.

It exposes the WSGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/5.0/howto/deployment/wsgi/
"""

import os
from django.core.wsgi import get_wsgi_application

# Set the Django settings module based on environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE','gidigo_server.settings_prod' if os.environ.get('DJANGO_ENV') == 'production'else 'gidigo_server.settings')

application = get_wsgi_application()
