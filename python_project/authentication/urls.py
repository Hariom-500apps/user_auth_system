from django.urls import path
from . import views

urlpatterns = [
    path('', views.DefaultRedirectView.as_view(), name='default_redirect'),  # Default redirect to register if not logged in
    path('login/', views.UserLoginView.as_view(), name='login'),
    path('register/', views.UserRegisterView.as_view(), name='register'),
    path('profile/', views.UserProfileView.as_view(), name='profile'),
    path('user/dashboard', views.UserDashboardView.as_view(), name='user_dashboard'),
    path('dashboard', views.AdminDashboardView.as_view(), name='dashboard'),
    path('logout/', views.LogoutView.as_view(), name='logout'),

]
