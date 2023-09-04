from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from apiapp.serializers import UserRegistrationSerializer, UserLoginSerializer,UserProfileSerializer,UserChangePasswordSerializer,SendPasswordEmailSerializer,EmailLinkPasswordResetSerializer,RestaurantSerializer,MenuItemCreateSerializer,UserLikeResSerializer,UserLikemenuSerializer,UsersavemenuSerializer,RestaurantsSerializer,UserputLikeResSerializer
from django.contrib.auth import authenticate
from rest_framework.exceptions import MethodNotAllowed
from apiapp .renderers import UserRenderer
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import IsAuthenticated,IsAdminUser
from apiapp.models import Restaurant,MenuItem
from rest_framework import status
from rest_framework import viewsets
from rest_framework.authentication import BasicAuthentication

#generate token manually
def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)

    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }

class UserRegistrationView(APIView):
    renderer_classes = [UserRenderer]
    def post(self, request, format=None):
        serializer = UserRegistrationSerializer(data = request.data )
        if serializer.is_valid(raise_exception=True):
            user = serializer.save()
            token = get_tokens_for_user(user)
            return Response({'token':token, 'msg':'Registration Success'})
        return Response(serializer.errors)
    

class UserLoginView(APIView):
    def post(self, request, format=None):
        serializer = UserLoginSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            email = serializer.data.get('email')
            password = serializer.data.get('password')
            user = authenticate(email=email, password=password)
            if user is not None:
                token = get_tokens_for_user(user)
                return Response({'token':token,'msg': 'Login Success'}, status=status.HTTP_200_OK)
            else:
                return Response({'errors': {'non_field_errors': ['Email or Password Not Valid']}}, status=status.HTTP_401_UNAUTHORIZED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class UserProfileView(APIView):
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]
    def get(self, request, format=None):
        serializer = UserProfileSerializer(request.user)
        # if serializer.is_valid():
        return Response(serializer.data)
    
class UserChangePasswordView(APIView):
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]
    def post(self, request, format=None):
        serializer = UserChangePasswordSerializer(data = request.data, context={'user':request.user})
        if serializer.is_valid(raise_exception=True):
            return Response({'msg':'password change successfully'})
        return Response(serializer.errors,status=status.HTTP_400_NOT_FOUNDS)
        
class SendPasswordEmailView(APIView):
    renderer_classes = [UserRenderer]
    def post(self, request, format=True):
        serializer = SendPasswordEmailSerializer(data = request.data)
        if serializer.is_valid(raise_exception=True):
            return Response({'msg':'password reset link send successfully'})
        return Response(serializer.errors,status=status.HTTP_400_NOT_FOUNDS)

class EmailLinkPasswordResetView(APIView):
    renderer_classes = [UserRenderer]
    def post(self, request, uid, token, format=True):
        serializer = EmailLinkPasswordResetSerializer(data=request.data,context={'uid':uid,'token':token})
        if serializer.is_valid(raise_exception=True):
            return Response({'msg':'password reset successfully'})
        return Response(serializer.errors,status=status.HTTP_400_NOT_FOUNDS)

class AllRestaurant(viewsets.ModelViewSet):
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]
    queryset = Restaurant.objects.all()
    serializer_class = RestaurantsSerializer

    def create(self, request, *args, **kwargs):
        raise MethodNotAllowed('POST')

#Add Restaurants
class Restaurantadd(viewsets.ModelViewSet):
    queryset = Restaurant.objects.all()
    serializer_class = RestaurantSerializer
    authentication_classes = [BasicAuthentication]
    permission_classes = [IsAdminUser]
    def list(self, request, *args, **kwargs):
        print("HTTP method: ", request.method)
        return super().list(request, *args, **kwargs)

    def create(self, request, *args, **kwargs):
        print("HTTP method: ", request.method)
        return super().create(request, *args, **kwargs)

class Restaurantmanuadd(viewsets.ModelViewSet):
    serializer_class = MenuItemCreateSerializer
    authentication_classes = [BasicAuthentication]
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        user_restaurant = Restaurant.objects.get(user=self.request.user)
        queryset = MenuItem.objects.filter(restaurant=user_restaurant)
        
        return queryset

    def perform_create(self, serializer):
        user_restaurant = Restaurant.objects.get(user=self.request.user)
        serializer.save(restaurant=user_restaurant)
   
   
class UserlikeRestaurant(APIView):
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]
    def post(self, request, format=None):
        serializer = UserLikeResSerializer(data = request.data, context={'user':request.user} )
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            print(serializer.data)
            if serializer.data['likes'] == True:
                return Response({'msg':'like/ Restaurant Success'})
            return Response({'msg':'dislike/ Restaurant Success'})
        return Response(serializer.errors)


class Userlikemenuitem(APIView):
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]
    def post(self, request, format=None):
        serializer = UserLikemenuSerializer(data = request.data, context={'user':request.user})
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            if serializer.data['likes'] == True:
                return Response({'msg':'like menu-iteam Success'})
            return Response({'msg':'unlike menu-iteam Success'})
        return Response(serializer.errors)
   
class Usersavemenuitem(APIView):
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]
    def post(self, request, format=None):
        serializer = UsersavemenuSerializer(data = request.data, context={'user':request.user})
        if serializer.is_valid(raise_exception=True):
            user = serializer.save()
            if serializer.data['sdate'] == True:
                return Response({'msg':'save menu Success'})
            return Response({'msg':'unsave menu Success'})
        return Response(serializer.errors)
   
   