from django.shortcuts import render

# Create your views here.

from django.views import View
from django.http.response import HttpResponseBadRequest
import re
from users.models import User
from django.db import DatabaseError
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
        # 4.保存响应，跳转页面
        #暂时返回一个注册成功的信息,后期再实现跳转到指定页面
        return HttpResponseBadRequest('注册成功,重定向到首页')


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
        return HttpResponse(image,content_type='image/jpeg')

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