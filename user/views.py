from django.shortcuts import redirect, render, HttpResponse
from django.contrib.auth import get_user_model, login, authenticate, logout, update_session_auth_hash
from django.contrib import messages
from django.core.mail import send_mail, EmailMessage
from django.template.loader import render_to_string

from djangoProject.settings import BASE_DIR
from .utils import account_activation_token
from django.utils.encoding import force_bytes, force_text
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.urls import reverse
from django.conf import settings
from django.contrib.auth.hashers import check_password, make_password
import json
import os
from datetime import datetime
import time
import json
from django.conf import settings
# Create your views here.
User = get_user_model()


def signup(request):
    if request.method == "POST":
        firstname = request.POST['first_name']
        lastname = request.POST['last_name']
        email = request.POST['email']
        password = request.POST['password']
        confirm_password = request.POST['confirm_password']
        if password == confirm_password:
            if User.objects.filter(email=email).exists():
                messages.error(request, 'Email already exists')
                return redirect('signup')
            else:
                user = User.objects.create_user(
                    username=email, email=email, password=password, first_name=firstname, last_name=lastname)
                user.save()
                login(request, user)
                messages.success(request, 'Successfully Registred')
                return redirect('loginProcess')
        else:
                messages.error(
                    request, "Confirm Password didn't matched with Password")

                return redirect("signup")
    return render(request, "signup.html")


def loginProcess(request):
    if request.method == "POST":
        if not request.user.is_authenticated:
                email = request.POST['email']
                password = request.POST['password']
                user = authenticate(username=email, password=password)
                if user:
                    login(request, user)
                    messages.success(request, "Successfully Login")
                    return redirect('dashboard')
                else:
                    messages.error(request, "Invalid Credentials")
                    return redirect('loginProcess')

        else:
            messages.error(request, "You are Already logged In")

    return render(request, "login.html")


def dashboard(request):
    if request.user.is_authenticated:
        seo = None
        seo_description = None
        accessibility = None
        accessibility_description = None
        performance = None
        best_practices = None
        audits = None
        url = None
        redirects = {}
        service = {}
        viewport = {}
        first_contentful_paint = {}
        largest_contentful_paint = {}
        first_meaningful_paint = {}
        speed_index = {}
        total_blocking_time = {}
        errors_in_console = {}
        server_response_time = {}
        redirects_overall = {}
        data = None
        data1 = None
        if request.method == "POST":
            print(request.POST)
            if 'domain_overview' in request.POST:
                url = request.POST['url_name']
                os.system('lighthouse --quiet --no-update-notifier --no-enable-error-reporting --output=json --output-path={}/report.json --chrome-flags="--headless" '.format(settings.BASE_DIR)+url)
                print("Report complete for: " + url)
                with open('{}/report.json'.format(settings.BASE_DIR),  "r",  encoding="utf8") as json_data:
                    loaded_json = json.load(json_data)
                if not round(loaded_json["categories"]["seo"]["score"] * 100):    
                    seo = str(
                        round(loaded_json["categories"]["seo"]["score"] * 100))
                    
                else: 
                    seo = int(
                        round(loaded_json["categories"]["seo"]["score"] * 100))
                seo_description = str(
                        loaded_json["categories"]["seo"]["description"])
                    
                if not round(loaded_json["categories"]["accessibility"]["score"] * 100):    
                    accessibility = str(
                        round(loaded_json["categories"]["accessibility"]["score"] * 100))
                else:
                    accessibility = int(
                        round(loaded_json["categories"]["accessibility"]["score"] * 100))
                
                
                    
                accessibility_description = str(
                        loaded_json["categories"]["accessibility"]["description"])
                
                
                if not loaded_json["categories"]["performance"]["score"] * 100:
                    performance = str(
                        round(loaded_json["categories"]["performance"]["score"] * 100))
                else:
                    performance = int(
                        round(loaded_json["categories"]["performance"]["score"] * 100))
                    
                if not loaded_json["categories"]["best-practices"]["score"] * 100: 
                    best_practices = str(
                        round(loaded_json["categories"]["best-practices"]["score"] * 100))
                else:
                    best_practices = int(
                        round(loaded_json["categories"]["best-practices"]["score"] * 100))
                data = True

            if 'btn_audit' in request.POST:
                search_audit = request.POST['search_audit']
                print(search_audit)
                os.system('lighthouse --quiet --no-update-notifier --no-enable-error-reporting --output=json --output-path={}/report.json --chrome-flags="--headless" '.format(settings.BASE_DIR)+search_audit)
                print("Report complete for: " + search_audit)
                with open('{}/report.json'.format(settings.BASE_DIR),  "r",  encoding="utf8") as json_data:
                    loaded_json = json.load(json_data)
                # Audit
                audits = str(
                    round(loaded_json["audits"]["is-on-https"]["score"] * 100))
                description = str(
                    loaded_json["audits"]["is-on-https"]["description"])

                redirects_http_score = str(
                    round(loaded_json["audits"]["redirects-http"]["score"] * 100))
                redirects_http_title = str(
                    loaded_json["audits"]["redirects-http"]["title"])
                redirects_http_desc = str(
                    loaded_json["audits"]["redirects-http"]["description"])
                print(redirects_http_desc)
                redirects = {'redirects_http_score': int(redirects_http_score),
                    'redirects_http_title': redirects_http_title, 'redirects_http_desc': redirects_http_desc}

                service_worker_score = str(
                    round(loaded_json["audits"]["service-worker"]["score"] * 100))
                service_worker_title = str(
                    loaded_json["audits"]["service-worker"]["title"])
                service_worker_desc = str(
                    loaded_json["audits"]["service-worker"]["description"])

                service = {'service_worker_score': int(service_worker_score),
                    'service_worker_title': service_worker_title, 'service_worker_desc': service_worker_desc}

                viewport_score = str(
                    round(loaded_json["audits"]["viewport"]["score"] * 100))
                viewport_title = str(
                    loaded_json["audits"]["viewport"]["title"])
                viewport_desc = str(
                    loaded_json["audits"]["viewport"]["description"])

                viewport = {'viewport_score': int(viewport_score),
                    'viewport_title': viewport_title, 'viewport_desc': viewport_desc}

                first_contentful_paint_score = str(
                    round(loaded_json["audits"]["first-contentful-paint"]["score"] * 100))
                first_contentful_paint_title = str(
                    loaded_json["audits"]["first-contentful-paint"]["title"])
                first_contentful_paint_desc = str(
                    loaded_json["audits"]["first-contentful-paint"]["description"])
                first_contentful_paint_display_time = str(
                    loaded_json["audits"]["first-contentful-paint"]["displayValue"])

                first_contentful_paint = {'first_contentful_paint_score': int(first_contentful_paint_score), 'first_contentful_paint_title': first_contentful_paint_title,
                    'first_contentful_paint_desc': first_contentful_paint_desc, 'first_contentful_paint_display_time': first_contentful_paint_display_time}

                largest_contentful_paint_score = str(
                    round(loaded_json["audits"]["largest-contentful-paint"]["score"] * 100))
                largest_contentful_paint_title = str(
                    loaded_json["audits"]["largest-contentful-paint"]["title"])
                largest_contentful_paint_desc = str(
                    loaded_json["audits"]["largest-contentful-paint"]["description"])
                largest_contentful_paint_display_time = str(
                    loaded_json["audits"]["largest-contentful-paint"]["displayValue"])

                largest_contentful_paint = {'largest_contentful_paint_score': int(largest_contentful_paint_score), 'largest_contentful_paint_title': largest_contentful_paint_title,
                    'largest_contentful_paint_desc': largest_contentful_paint_desc, 'largest_contentful_paint_display_time': largest_contentful_paint_display_time}

                first_meaningful_paint_score = str(
                    round(loaded_json["audits"]["first-meaningful-paint"]["score"] * 100))
                first_meaningful_paint_title = str(
                    loaded_json["audits"]["first-meaningful-paint"]["title"])
                first_meaningful_paint_desc = str(
                    loaded_json["audits"]["first-meaningful-paint"]["description"])
                first_meaningful_paint_display_time = str(
                    loaded_json["audits"]["first-meaningful-paint"]["displayValue"])

                first_meaningful_paint = {'first_meaningful_paint_score': int(first_meaningful_paint_score), 'first_meaningful_paint_title': first_meaningful_paint_title,
                    'first_meaningful_paint_desc': first_meaningful_paint_desc, 'first_meaningful_paint_display_time': first_meaningful_paint_display_time}

                speed_index_score = str(
                    round(loaded_json["audits"]["speed-index"]["score"] * 100))
                speed_index_title = str(
                    loaded_json["audits"]["speed-index"]["title"])
                speed_index_desc = str(
                    loaded_json["audits"]["speed-index"]["description"])
                speed_index_display_time = str(
                    loaded_json["audits"]["speed-index"]["displayValue"])

                speed_index = {'speed_index_score': int(speed_index_score), 'speed_index_title': speed_index_title,
                    'speed_index_desc': speed_index_desc, 'speed_index_display_time': speed_index_display_time}

                total_blocking_time_score = str(
                    round(loaded_json["audits"]["total-blocking-time"]["score"] * 100))
                total_blocking_time_title = str(
                    loaded_json["audits"]["total-blocking-time"]["title"])
                total_blocking_time_desc = str(
                    loaded_json["audits"]["total-blocking-time"]["description"])
                total_blocking_time_time = str(
                    loaded_json["audits"]["total-blocking-time"]["displayValue"])

                total_blocking_time = {'total_blocking_time_score': int(total_blocking_time_score), 'total_blocking_time_title': total_blocking_time_title,
                    'total_blocking_time_desc': total_blocking_time_desc, 'total_blocking_time_time': total_blocking_time_time}

                errors_in_console_score = str(
                    round(loaded_json["audits"]["errors-in-console"]["score"] * 100))
                errors_in_console_title = str(
                    loaded_json["audits"]["errors-in-console"]["title"])
                errors_in_console_desc = str(
                    loaded_json["audits"]["errors-in-console"]["description"])

                errors_in_console = {'errors_in_console_score': int(errors_in_console_score),
                    'errors_in_console_title': errors_in_console_title, 'errors_in_console_desc': errors_in_console_desc}

                server_response_time_score = str(
                    round(loaded_json["audits"]["server-response-time"]["score"] * 100))
                server_response_time_title = str(
                    loaded_json["audits"]["server-response-time"]["title"])
                server_response_time_desc = str(
                    loaded_json["audits"]["server-response-time"]["description"])

                server_response_time = {'server_response_time_score': int(server_response_time_score),
                    'server_response_time_title': server_response_time_title, 'server_response_time_desc': server_response_time_desc}

                redirects_score = str(
                    round(loaded_json["audits"]["redirects"]["score"] * 100))
                redirects_title = str(
                    loaded_json["audits"]["redirects"]["title"])
                redirects_desc = str(
                    loaded_json["audits"]["redirects"]["description"])

                redirects_overall = {'redirects_score': int(redirects_score),
                    'redirects_title': redirects_title, 'redirects_desc': redirects_desc}

                data1 = True

        return render(request, 'dashboard.html', {'data': data,'data1':data1 ,'redirects': redirects, 'service': service, 'viewport': viewport, 'first_contentful_paint': first_contentful_paint, 'largest_contentful_paint': largest_contentful_paint, 'first_meaningful_paint': first_meaningful_paint, 'speed_index': speed_index, 'errors_in_console': errors_in_console, 'total_blocking_time': total_blocking_time, 'server_response_time': server_response_time, 'redirects_overall': redirects_overall, 'seo':seo, 'seo_description': seo_description, 'accessibility': accessibility, 'accessibility_description': accessibility_description, 'performance': performance,   'best_practices': best_practices, 'audits': audits})
    else:    
         return redirect("loginProcess")   

def updatepassword(request):
    if request.user.is_authenticated:
        if request.method == "POST":
            old_password = request.POST['current_password']
            new_password = request.POST['new_password']
            confirm_password = request.POST['confirm_password']
            if check_password(old_password,request.user.password):
                if new_password == confirm_password:
                    request.user.password = make_password(new_password)
                    request.user.save()
                    update_session_auth_hash(request, request.user)
                    messages.success(request,'Password Updated Succesfully')
                    
                else:
                    messages.error(request,'Please Enter Same Password and Confirm Password')
            else:
                messages.error(request,"Please Enter Valid Current Password")
            return redirect('dashboard')
        else:
           return render(request, 'updatepassword.html')

    

def forgetpassword(request):
    if request.method == "POST":
        email = request.POST['email']
        if User.objects.filter(email=email).exists():
            user = User.objects.get(email=email)
            current_site = settings.HOST_URL
            email_body={
                        'user':user,
                        'domain':current_site,
                        'uid':urlsafe_base64_encode(force_bytes(user.pk)),
                        'token':account_activation_token.make_token(user)
            }
            link = reverse('confirmforgotPassword', kwargs={
                        'uidb64': email_body['uid'], 'token': email_body['token']})

            email_subject = 'Reset Your Account Password'

            activate_url = 'http://' + current_site + link
            print(activate_url)
            
            # plain_message = strip_tags(html_message)
            from_email = settings.EMAIL_HOST_USER,
            print(from_email)
            to = email
            print(to)
            # send_mail(email_subject, None, from_email, [to],html_message=html_message)

            # message = get_template('forgotPasswordMail.html').render_to()
            send_mail(
                email_subject,
                "To Change your password Please click this link : "+activate_url,
                from_email[0],
                [to],
            )
            messages.info(request,"Confirmation Email for Reset Password was sent")
        else:
            messages.error(request,'Email Not Exist')
        return redirect("forgetpassword")
        
        
    return render(request, 'forgetpassword.html')


def confirmforgotPassword(request, uidb64, token):
    try:
        uid = force_text(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except(TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None
    if user is not None and account_activation_token.check_token(user, token):
        
        return render(request,'forgotPasswordForm.html',{'email':user.email})
    else:
        messages.error('Activation link is invalid!')
        return redirect('login')

def confirmforgotPasswordForm(request):
    if request.method == "POST":
        email = request.POST['email']
        if User.objects.filter(email=email).exists():
            user = User.objects.get(email=email)
            password = request.POST['password']
            confirm_password = request.POST['confirm_password']
            if password == confirm_password:
                user.password = make_password(password)
                user.save()
                update_session_auth_hash(request, request.user)
                messages.success(request,"Password Updated Successfully ! You can Login with New Password Now")
                return redirect('loginProcess')
            else:
                messages.error(request,'Password and Confirm Password Not Matched')
                return render(request,'forgotPasswordForm.html',{'email':email})
        else:
            messages.error(request,'Email Not Exist')
            return redirect('forgotpassword')
    else:
        return HttpResponse("Method Not Allowed")

def logoutProcess(request):
    if request.user.is_authenticated:
        logout(request)

    return redirect('index')



    
