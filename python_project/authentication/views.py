# views.py
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login
from django.views.generic import TemplateView, View
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView
from .models import CustomUser as User
from rest_framework_simplejwt.tokens import RefreshToken
from . import serializers
from rest_framework import status
from django.http import JsonResponse
from django.contrib.auth import logout



class LogoutView(View):
    def post(self, request):
        logout(request)  # Log the user out
        return render(request, 'authentication/register.html')

class UserLoginView(APIView):
    authentication_classes = []
    permission_classes = []

    def get(self, request):
        return render(request, 'authentication/login.html')


    def post(self, request):
        context = {
            "success": 1,
            "message": "User logged in successfully",
            "data": {}
        }
        try:
            email = request.data.get("email")
            password = request.data.get("password")
            auth_user = authenticate(request, username=email, password=password)

            if auth_user is not None:
                if not auth_user.is_active:
                    context['success'] = 0
                    context['message'] = "This account is inactive."
                    return JsonResponse(context, status=status.HTTP_403_FORBIDDEN)

                login(request, auth_user)
                refresh = RefreshToken.for_user(auth_user)
                tokens = {
                    'access': str(refresh.access_token),
                    'refresh': str(refresh),
                }

                context['data'] = tokens
                context['user_role'] = 'admin' if auth_user.is_superuser else 'user'

                if auth_user.is_superuser:
                    return JsonResponse({
                        'success': 1,
                        'message': 'Welcome to Admin Dashboard',
                        'user_role': 'admin',
                        'data': tokens,
                    })
                else:
                    return JsonResponse({
                        'success': 1,
                        'message': 'Welcome to User Dashboard',
                        'user_role': 'user',
                        'data': tokens,
                    })
            else:
                context['success'] = 0
                context['message'] = "Invalid credentials"
                return JsonResponse(context, status=status.HTTP_401_UNAUTHORIZED)

        except Exception as e:
            context['success'] = 0
            context['message'] = str(e)
            return JsonResponse(context, status=status.HTTP_400_BAD_REQUEST)

class DefaultRedirectView(View):
    def get(self, request):
        if request.user.is_authenticated:
            return redirect('user/dashboard')
        return redirect('/register')

class UserRegisterView(APIView):
    authentication_classes = []
    permission_classes = []

    def get(self, request):
        return render(request, 'authentication/login.html')


    def post(self, request):
        context = {
            "success": 1,
            "message": "User created successfully",
            "data": {},
        }

        try:
            username = request.data.get("username")
            email = request.data.get("email")
            password = request.data.get("password")
            password_confirm = request.data.get("password_confirm")

            # Validate password confirmation
            if password != password_confirm:
                raise Exception("Passwords do not match.")

            # Check if the username or email already exists using the custom user model
            if User.objects.filter(username=username).exists() or User.objects.filter(email=email).exists():
                raise Exception("Username or email already taken")

            # Create user using the custom user model
            user = User.objects.create_user(username=username, email=email, password=password)
            context['data'] = {'username': user.username, 'email': user.email}

            return JsonResponse(context)  # Return success message

        except Exception as e:
            context['success'] = 0
            context['message'] = str(e)
            return JsonResponse(context)

class UserProfileView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        context = {
            "success": 1,
            "message": 'Profile details fetched successfully.',
            "data": {}
        }
        try:
            user = request.user
            serializer = serializers.UserProfileSerializer(user)
            context['data'] = serializer.data
        except Exception as e:
            context['success'] = 0
            context['message'] = str(e)
        return JsonResponse(context)

class AdminDashboardView(TemplateView):
    template_name = 'authentication/dashboard.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        users = User.objects.all()
        context['users'] = users
        context['message'] = "Welcome to the Admin Dashboard"

        return context

# User Dashboard View
class UserDashboardView(TemplateView):
    template_name = 'authentication/user_dashboard.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['message'] = "Welcome to the User Dashboard"
        return context
