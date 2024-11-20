from django.contrib import admin
from app.models import User
from .models import User
from app.models import InsecureUser, SecureUser

admin.site.register(User)
admin.site.register(InsecureUser)
admin.site.register(SecureUser)

# Register your models here.
