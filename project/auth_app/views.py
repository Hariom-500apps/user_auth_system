from django.contrib.auth.models import User
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.tokens import RefreshToken
from .serializers import UserSerializer, LoginSerializer, ProfileSerializer, TokenSerializer

class RegisterView(APIView):
    def post(self, request):
        try:
            serializer = UserSerializer(data=request.data)
            if serializer.is_valid():
                user = serializer.save()
                return Response({"message": "User registered successfully"})
            return Response(serializer.errors, status=400)
        except Exception as e:
            raise ValueError(str(e))


class LoginView(APIView):
    def post(self, request):
        try:
            serializer = LoginSerializer(data=request.data)
            if serializer.is_valid():
                user = serializer.validated_data
                refresh = RefreshToken.for_user(user)
                access_token = refresh.access_token
                return Response({
                    'refresh': str(refresh),
                    'access': str(access_token)
                })
            return Response({'error': 'Invalid credentials'}, status=400)
        except Exception as e:
            raise ValueError(str(e))


class ProfileView(APIView):
     authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        profile = Profile.objects.get(user=request.user)
        serializer = ProfileSerializer(profile)
        return Response(serializer.data)
