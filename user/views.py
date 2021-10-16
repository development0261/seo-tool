from django.shortcuts import redirect, render, HttpResponse
from django.contrib.auth import get_user_model,login,authenticate,logout,update_session_auth_hash
from django.contrib import messages
from django.core.mail import send_mail,EmailMessage
from django.template.loader import render_to_string
from .utils import account_activation_token
from django.utils.encoding import force_bytes,force_text
from django.utils.http import urlsafe_base64_decode,urlsafe_base64_encode
from django.urls import reverse
from django.conf import settings
from django.contrib.auth.hashers import check_password, make_password
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
                messages.error(request,'Email already exists')
                return redirect('register')
            else:
                user=User.objects.create_user(username=email,email=email,password=password,first_name=firstname,last_name=lastname)
                user.save()
                login(request,user)
                messages.success(request,'Successfully Registered')
                return redirect('loginProcess')
        else:
                messages.error(request,"Confirm Password didn't matched with Password")

                return redirect("signup")
    return render(request,"signup.html")

def loginProcess(request):
    if request.method == "POST":
        if not request.user.is_authenticated:
                email = request.POST['email']
                password = request.POST['password']
                user=authenticate(username=email,password=password)
                if user:
                    login(request,user)
                    messages.success(request,"Successfully Login")
                    return redirect('dashboard')
                else:
                    messages.error(request,"Invalid Credentials")
                    return redirect('loginProcess')

        else:
            messages.error(request,"You are Already logged In")

    return render(request,"login.html")

def dashboard(request):
    return render(request, 'dashboard.html')

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