from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django.contrib.auth.models import User
from allauth.socialaccount.models import SocialAccount, SocialToken, SocialApp

admin.site.unregister(User)

@admin.register(User)
class MemprobeUserAdmin(UserAdmin):
    list_display  = ('email', 'date_joined', 'last_login', 'is_active', 'is_staff')
    list_filter   = ('is_active', 'is_staff', 'date_joined')
    search_fields = ('email', 'username')
    ordering      = ('-date_joined',)
    readonly_fields = ('date_joined', 'last_login')

admin.site.unregister(SocialAccount)

@admin.register(SocialAccount)
class SocialAccountAdmin(admin.ModelAdmin):
    list_display  = ('user', 'provider', 'date_joined', 'last_login')
    list_filter   = ('provider',)
    search_fields = ('user__email',)
    readonly_fields = ('user', 'provider', 'uid', 'date_joined', 'last_login', 'extra_data')

admin.site.unregister(SocialToken)
admin.site.unregister(SocialApp)
