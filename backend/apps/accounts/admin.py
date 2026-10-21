from django.contrib import admin

from .models import Membership, Tenant, User

admin.site.register(Tenant)
admin.site.register(User)
admin.site.register(Membership)
