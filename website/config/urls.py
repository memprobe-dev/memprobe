"""Root URL configuration."""

from django.urls import path, include

urlpatterns = [
    path('', include('webapp.urls')),
    path('accounts/', include('allauth.urls')),
]
