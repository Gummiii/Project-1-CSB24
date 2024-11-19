"""
URL configuration for webapp2 project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include
from app import views

urlpatterns = [
    path('admin/', admin.site.urls),
    path('login/', views.login_view, name='login'),
    path('', views.index, name='index'),
    path('vulnerable_sql', views.vulnerable_sql, name='vulnerable_sql'),
    path('secure_sql', views.secure_sql, name='secure_sql'),
    path('view_user_data/<int:user_id>', views.view_user_data, name='view_user_data'),
    path('secure_view_user_data/<int:user_id>', views.secure_view_user_data, name='secure_view_user_data'),
    path('fetch_url', views.fetch_url, name='fetch_url'),
]
