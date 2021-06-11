from django.shortcuts import render

# Create your views here.

from django.views import View
from django.http.response import HttpResponseBadRequest
import re
from users.models import User
from django.db import DatabaseError
from django.shortcuts import redirect
from django.urls import reverse

# 注册视图
class RegisterView(View):

    def get(self, request):


        return render(request, 'register.html')
    def post(self,request):
        """
        1.接收前端的数据
        2.验证数据
            2.1 参数是否齐全
            2.2 手机号的格式是否正确
            2.3 密码是否符合格式
            2.4 密码和确认密码要一致
            2.5 短信验证码是否和redis中的一致
        3.保存注册信息
        4.保存响应，跳转页面
        :param reuqest:
        :return:
        """
        # 1.接收前端的数据
        mobile = request.POST.get('mobile')
        password = request.POST.get('password')
        password2 = request.POST.get('password2')
        smscode = request.POST.get('sms_code')
        # 2.验证数据
        #     2.1参数是否齐全
        if not all([mobile,password,password2,smscode]):
            return HttpResponseBadRequest('缺少必要的参数')
        #     2.2手机号的格式是否正确
        if not re.match(r'^1[3-9]\d{9}$',mobile):
            return HttpResponseBadRequest('手机号的格式错误')
        #     2.3密码是否符合格式
        if not re.match(r'^[0-9A-Za-z]{8,20}$',password):
            return HttpResponseBadRequest('请输入8-20位密码，密码是数字，字母')
        #     2.4密码和确认密码要一致
        if password != password2:
            return HttpResponseBadRequest('两次密码不一致')
        #     2.5短信验证码是否和redis中的一致
        redis_conn = get_redis_connection('default')
        redis_sms_code = redis_conn.get('sms:%s'%mobile)
        if redis_sms_code is None:
            return HttpResponseBadRequest('短信验证码已过期')
        if smscode != redis_sms_code.decode():
            return HttpResponseBadRequest('短信验证码不一致')
        # 3.保存注册信息
        # create_user 可以使用系统的方法对密码进行加密
        try:
            user = User.objects.create_user(username=mobile,
                                            mobile=mobile,
                                            password=password)
        except DatabaseError as e:
            logger.error(e)
            return HttpResponseBadRequest('注册失败')
        # 状态保持
        from django.contrib.auth import login
        login(request, user)
        # 4.保存响应，跳转页面
        #暂时返回一个注册成功的信息,后期再实现跳转到指定页面
        # return HttpResponseBadRequest('注册成功,重定向到首页')
        # redirect 进行重定向
        # reverse 通过namespase：name 获取到视图对应的路由
        response = redirect(reverse('home:index'))
        #设置cookie信息，方便用户信息展示的判断和用户信息的展示
        response.set_cookie('is_login',True)
        response.set_cookie('username',user.username,max_age=7*24*3600)
        return response

# 图片验证码视图
from django.http.response import HttpResponseBadRequest
from libs.captcha.captcha import captcha
from django_redis import get_redis_connection
from django.http import HttpResponse

class ImageCodeView(View):

    def get(self,request):
        """
        接收前端传递的uuid
        判断uuid是否获取到
        通过调用captcha来生成图片验证码(图片二进制和图片内容)
        将图片内容保存到redis中
            uuid作为一个key,图片内容作为一个value,同时还需要设置一个时效
        返回图片二进制文件
        :param request:
        :return:
        """
        # 接收前端传递的uuid
        uuid = request.GET.get('uuid')
        # 判断uuid是否获取到
        if uuid is None:
            return HttpResponseBadRequest('没有传递uuid')
        # 通过调用captcha来生成图片验证码(图片二进制和图片内容)
        text,image = captcha.generate_captcha()
        # 将图片内容保存到redis中
        # uuid作为一个key, 图片内容作为一个value, 同时还需要设置一个时效
        redis_conn = get_redis_connection('default')
        # redis_conn.setex(key,seconds,value)
        # key  设置为uuid
        # seconds 过期秒数 300秒 5分钟
        # value text
        redis_conn.setex('img:%s' % uuid, 300, text)
        # 返回图片二进制文件
        return HttpResponse(image, content_type='image/jpeg')

# 短信验证码视图
from django.http.response import JsonResponse
from utils.response_code import RETCODE
import logging
logger = logging.getLogger('django')
from random import randint
from libs.yuntongxun.sms import CCP

class SmsCodeView(View):

    def get(self,request):
        """
        1.接收参数
        2.参数验证
            2.1验证参数是否齐全
            2.2图片验证码的验证
                连接redis,获取redis中的图片验证
                判断图片是否存在
                如果图片未过期,则获取到之后进行删除
                对比图片验证码
        3.生成短信验证码
        4.保存短信验证码到redis中
        5.发送短信
        6.返回响应
        :param request:
        :return:
        """
        # 1.接收参数
        mobile = request.GET.get('mobile')
        image_code = request.GET.get('image_code')
        uuid = request.GET.get('uuid')
        # 2.参数验证
        #    2.1验证参数是否齐全
        if not all([mobile,image_code,uuid]):
            return JsonResponse({'code':RETCODE.NECESSARYPARAMERR,'errmsg':'缺少必要的参数'})
        #    2.2图片验证码的验证
        #           连接redis, 获取redis中的图片验证
        redis_conn = get_redis_connection('default')
        redis_image_code = redis_conn.get('img:%s'%uuid)
        #            判断图片是否存在
        if redis_image_code is None:
            return JsonResponse({'code':RETCODE.IMAGECODEERR,'errmsg':'图片验证码已过期'})
        #            如果图片未过期, 则获取到之后进行删除
        try:
            redis_conn.delete('img:%s'%uuid)
        except Exception as e:
            logger.error(e)
        # 对比图片验证码 处理验证码的大小写问题, redis的数据是bytes类型
        if redis_image_code.decode().lower() != image_code.lower():
            return JsonResponse({'code':RETCODE.IMAGECODEERR,'errmsg':'图片验证码错误'})
        # 生成随机6位短信验证码
        sms_code = '%06d'%randint(0,999999)
        # 为了后期比对的方便,将短信验证码记录到日志中
        logger.info(sms_code)
        # 4.保存短信验证码到redis中
        redis_conn.setex('sms:%s'%mobile,300,sms_code)
        # 5.发送短信
        CCP().send_template_sms(mobile,[sms_code,5],1)
        # 6.返回响应
        return JsonResponse({'code':RETCODE.OK,'errmsg':'短信发送成功！'})


#登陆页面视图
from django.views import View
from django.contrib.auth import login
from django.contrib.auth import authenticate


class LoginView(View):

    def get(self, request):
        """
        #1. 接收参数
        #2.参数验证
        #3.用户认证登陆
        #4.状态的保持
        #5.更具用户的选择是否记住登陆状态进行判断
        #6.为了首页显示我们需要设置一些cookie信息
        #7.返回响应
        :param request:
        :return:
        """
        return render(request, 'login.html')

    def post(self, request):
        # 1. 接收参数
        mobile = request.POST.get('mobile')
        password = request.POST.get('password')
        remember = request.POST.get('remember')
        # 2.参数验证
            #2.1验证手机号是否符合规则
        if not re.match(r'^1[3-9]\d{9}$',mobile):
            return HttpResponseBadRequest('手机号不符合规则')
            #2.2验证密码是否符合规则
        if not re.match(r'^[a-zA-Z0-9]{8,20}$',password):
            return HttpResponseBadRequest('密码不符合规则')
        # 3.用户认证登陆
        #采用系统自带的方法进行验证,若用户名和密码正确返回user,否则返回None
        #默认的认证方法是正对于uesrname进行的判断
        # 当前判断的信息是手机号,所以需要修改认证字段,需要到User模型重进行修改
        user = authenticate(mobile=mobile,password=password)
        if user is None:
            return HttpResponseBadRequest('用户名或密码错误')
        # 4.状态的保持
        login(request,user)
        # 响应登陆即结果
        # 实现状态保持
        login(request, user)

        # 响应登录结果，根据next参数进行页面的跳转
        next = request.GET.get('next')
        if next:
            response = redirect(next)
        else:
            response = redirect(reverse('home:index'))
        # 5.更具用户的选择是否记住登陆状态进行判断
        if remember != 'on':    #没有记住用户信息
            # 浏览器关闭之后
            request.session.set_expiry(0)
            # 设置cookie信息
            response.set_cookie('is_login',True)
            response.set_cookie('username',user.username,max_age=14*24*3600)
        else:
        #     记住用户登陆状态:None表示两周后过期
            request.session.set_expiry(None)
        # 6.为了首页显示我们需要设置一些cookie信息
            response.set_cookie('is_login',True,max_age=14*24*3600)
            response.set_cookie('username',user.username,max_age=14*24*3600)
        # 7.返回响应
        return response


#退出登陆视图
from django.contrib.auth import logout


class LogoutView(View):

    def get(self,request):
        #1.session数据删除
        logout(request)
        # 重定向到登陆页
        response = redirect(reverse('home:index'))
        # 2.删除cookie数据
        response.delete_cookie('is_login')
        #3.跳转到首页
        return response


#忘记密码视图
class ForgetPasswordView(View):

    def get(self,request):

        return render(request,'forget_password.html')
    def post(self,request):
        """
        1.接收数据
        2.验证数据
            2.1判断参数是否齐全
            2.2手机号是否符合规则
            2.3密码是否符合规则
            2.4密码和确认密码是否一致
            2.5判断短信验证码是否正确
        3.根据手机号进行用户信息的查询
            3.1如果手机号查询出用户信息则进行密码的修改
            3.2如果手机号没有查询到用户信息，则进行新用户的创建
        4.页面的跳转，跳转到登录页面
        5.返回响应
        :param request:
        :return:
        """
        # 1.接收数据
        mobile = request.POST.get('mobile')
        password = request.POST.get('password')
        password2 = request.POST.get('password2')
        smscode = request.POST.get('sms_code')
        # 2.验证数据
        #     2.1判断参数是否齐全
        if not all([mobile,password,password2,smscode]):
            return HttpResponseBadRequest('参数不全')
        #     2.2手机号是否符合规则
        if not re.match(r'^1[3-9]\d{9}$',mobile):
            return HttpResponseBadRequest('手机号不符合规则')
        #     2.3密码是否符合规则
        if not re.match(r'^[0-9a-zA-Z]{8,20}$',password):
            return HttpResponseBadRequest('密码不符合规则')
        #     2.4密码和确认密码是否一致
        if password != password2:
            return HttpResponseBadRequest('密码不一致')
        #     2.5判断短信验证码是否正确
        redis_conn = get_redis_connection('default')
        redis_sms_code = redis_conn.get('sms:%s'%mobile)
        if redis_sms_code is None:
            return HttpResponseBadRequest('验证码以过期')
        if redis_sms_code.decode() != smscode:
            return HttpResponseBadRequest('短信验证码错误')
        # 3.根据手机号进行用户信息的查询
        try:
            user = User.objects.get(mobile=mobile)
        except User.DoesNotExist:
        #     3.2如果手机号没有查询到用户信息，则进行新用户的创建
            try:
                User.objects.create_user(username=mobile,
                                     mobile=mobile,
                                     password=password)
            except Exception:
                return HttpResponseBadRequest('修改失败,请稍候再试')
        else:
        #     3.1如果手机号查询出用户信息则进行密码的修改
            user.set_password(password)
            #注意保存用户信息
            user.save()
        # 4.页面的跳转，跳转到登录页面
        response = redirect(reverse('users:login'))
        # 5.返回响应
        return response


#用户中心展示
from django.views import View
from django.contrib.auth.mixins import LoginRequiredMixin

#LoginREquiredMixin若用户未登录，则会进行默认的跳转，默认跳转链接是：accounts/login/？next=xxx
class UserCenterView(LoginRequiredMixin, View):

    def get(self,request):
        #获取登陆用户的信息
        user=request.user
        #组织获取用户的信息
        context = {
            'username': user.username,
            'mobile': user.mobile,
            'avatar': user.avatar.url if user.avatar else None,
            'user_desc': user.user_desc
        }
        return render(request,'center.html',context=context)

    def post(self, request):
        # 接收数据
        user = request.user
        avatar = request.FILES.get('avatar')
        username = request.POST.get('username', user.username)
        user_desc = request.POST.get('desc', user.user_desc)

        # 修改数据库数据
        try:
            user.username = username
            user.user_desc = user_desc
            if avatar:
                user.avatar = avatar
            user.save()
        except Exception as e:
            logger.error(e)
            return HttpResponseBadRequest('更新失败，请稍后再试')

        # 返回响应，刷新页面
        response = redirect(reverse('users:center'))
        # 更新cookie信息
        response.set_cookie('username', user.username, max_age=14 * 24 * 3600)
        return response


