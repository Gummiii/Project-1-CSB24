from django.contrib.auth.models import AbstractBaseUser, BaseUserManager
from django.db import models

class UserManager(BaseUserManager):
    def create_user(self, username, email, password=None):
        if not email:
            raise ValueError('Users must have an email address')
        user = self.model(
            username=username,
            email=self.normalize_email(email),
        )
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, username, email, password=None):
        user = self.create_user(
            username=username,
            email=email,
            password=password,
        )
        user.is_admin = True
        user.save(using=self._db)
        return user


class User(AbstractBaseUser):
    username = models.CharField(max_length=150, unique=True)
    email = models.EmailField(unique=True)
    is_active = models.BooleanField(default=True)
    is_admin = models.BooleanField(default=False)

    objects = UserManager()

    USERNAME_FIELD = 'username'  # Primary field for authentication
    REQUIRED_FIELDS = ['email']  # Required for creating superusers

    def __str__(self):
        return self.username

    @property
    def is_staff(self):
        """Is the user a member of staff?"""
        return self.is_admin

    def has_perm(self, perm, obj=None):
        """Does the user have a specific permission?"""
        return True  # Superusers or admins have all permissions by default

    def has_module_perms(self, app_label):
        """Does the user have permissions to view the app `app_label`?"""
        return True  # Admins have permissions for all apps

# A02:2021 Cryptographic Failures: The application uses weak or insecure cryptographic algorithms to protect sensitive data.

class InsecureUser(models.Model):
    username = models.CharField(max_length=100, unique=True)
    email = models.EmailField()
    password = models.CharField(max_length=100) # Especially this line, the password should be atleast hashed.



            ### SOLUTION ###
### (Uncomment below for safe code) ###

# from django.contrib.auth.hashers import make_password, check_password
# class User(models.Model):
#    username = models.CharField(max_length=100)
#    password = models.CharField(max_length=100)

#    def set_password(self, raw_password):
#        self.password = make_password(raw_password)

#    def check_password(self, raw_password):
#        return check_password(raw_password, self.password)
