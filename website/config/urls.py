"""Root URL configuration."""

from django.urls import path, include

urlpatterns = [
    # Our app (includes /login, /logout, all API routes)
    path('', include('webapp.urls')),
    # allauth handles OAuth callbacks, token exchange, etc.
    # Our custom /login page links to these provider URLs.
    path('accounts/', include('allauth.urls')),
]
