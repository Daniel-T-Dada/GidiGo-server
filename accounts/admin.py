from django.contrib import admin
from .models import CustomUser, UserSession


@admin.register(CustomUser)
class UserAdmin(admin.ModelAdmin):

    list_display = ['username', 'email', 'first_name',
                    'last_name', 'role', 'is_active']
    list_editable = ['first_name', 'last_name', 'role', 'is_active']
    list_display_links = ['username', 'email']
    # search_fields = ['username', 'email', 'first_name', 'last_name']
    # list_filter = ['is_active', 'is_staff', 'is_superuser', 'role']
    ordering = ['-date_joined']
    # fieldsets = (
    #     (None, {'fields': ('username', 'password')}),
    #     ('Personal info', {'fields': ('first_name', 'last_name', 'email')}),
    #     ('Permissions', {'fields': ('is_active','is_staff', 'is_superuser', 'is_admin', 'role')}),
    #     ('Important dates', {'fields': ('last_login', 'date_joined')}),
    # )


@admin.register(UserSession)
class UserSessionAdmin(admin.ModelAdmin):
    list_display = ['user', 'device_type', 'browser',
                    'ip_address', 'last_activity', 'is_active']
    list_filter = ['device_type', 'is_active']
    search_fields = ['user__username', 'browser', 'ip_address']
    ordering = ['-last_activity']
