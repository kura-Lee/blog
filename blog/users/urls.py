#进行users 子应用的视图路由
from django.urls import path

from users.views import RegisterView,ImageCodeView,SmsCodeView
urlpatterns = [
    #path的第一个参数：路由
    #path的第二个参数：视图函数名
    # 参数3：路由名，方便通过reverse来获取路由
    path('register/', RegisterView.as_view(), name='register'),

    #图片验证码的路由
    path('imagecode/',ImageCodeView.as_view(),name='imagecode'),

    # 短信验证码路由
    path('smscode/',SmsCodeView.as_view(),name='smscode')
]

from users.views import RegisterView
urlpatterns = [
    #path的第一个参数：路由
    #path的第二个参数：视图函数名
    path('register/', RegisterView.as_view(), name='register'),
]
