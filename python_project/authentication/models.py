from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.utils.translation import gettext_lazy as _
from django.db import models
from django.utils import timezone

class CustomUserManager(BaseUserManager):
    def create_user(self, username, password=None, **extra_fields):
        """Create and return a regular user with an encrypted password."""
        if not username:
            raise ValueError("The Username field must be set")
        
        user = self.model(username=username, **extra_fields)
        if password:
            user.set_password(password)
        user.save(using=self._db)
        return user

    def create_admin(self, username, password=None, **extra_fields):
        """Create and return an admin user."""
        user = self.model(username=username, user_type=CustomUser.UserType.ADMIN, **extra_fields)
        if password:
            user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        """Create and return a superuser."""
        # Ensure is_staff and is_superuser are set to True
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_admin', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('user_type', CustomUser.UserType.SUPER_ADMIN)

        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff=True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')
        
        if not email:
            raise ValueError('Superuser must have an email address.')
        user = self.model(email=email, **extra_fields)
        
        if password:
            user.set_password(password)
        user.save(using=self._db)
        return user
    
    def get_customers(self):
        """Return a queryset of active customers."""
        return super().get_queryset().filter(user_type=CustomUser.UserType.USER, is_active=True)

class CustomUser(AbstractBaseUser, PermissionsMixin):
    class UserType(models.TextChoices):
        SUPER_ADMIN = "super_admin", _("Super Admin")
        ADMIN = "admin", _("Admin")
        STAFF = "staff", _("Staff")
        USER = "user", _("User")

    username = models.CharField(max_length=50, null=False, blank=False, unique=True)
    email = models.EmailField(unique=True, null=True, blank=False)
    password = models.CharField(max_length=255, null=True, blank=False)
    is_superuser = models.BooleanField(default=False)
    is_admin = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)
    user_type = models.CharField(max_length=50, choices=UserType.choices, default=UserType.USER)
    is_active = models.BooleanField(default=True)
    objects = CustomUserManager()

    USERNAME_FIELD = 'email'  
    REQUIRED_FIELDS = ['username'] 
    class Meta:
        db_table = 'users' 
