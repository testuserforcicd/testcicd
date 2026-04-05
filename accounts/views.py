from django.shortcuts import render, redirect
from django.contrib.auth import get_user_model
import uuid
from .forms import RegistrationForm
from django.contrib.auth.decorators import login_required
from django.core.mail import send_mail
from django.conf import settings
from django_otp.plugins.otp_totp.models import TOTPDevice
import qrcode
import io
import base64
from django_otp import user_has_device
from django_otp import login as otp_login


User = get_user_model()

def verify_email(request, token):
    try:
        user = User.objects.get(email_verification_token=token)
        user.is_active = True
        user.is_email_verified = True
        user.email_verification_token = None
        user.save()
        return render(request, 'accounts/verify_success.html')
    except User.DoesNotExist:
        return render(request, 'accounts/error.html', {'message': 'Неверный токен'})

def register_view(request):
    if request.method == 'POST':
        form = RegistrationForm(request.POST)
        if form.is_valid():
            user = User.objects.create_user(
                username=form.cleaned_data['username'],
                email=form.cleaned_data['email'],
                password=form.cleaned_data['password']
            )
            user.is_active = False 
            user.email_verification_token = str(uuid.uuid4())
            user.save()

            verify_url = f"http://127.0.0.1:8000/verify/{user.email_verification_token}/"

            subject = "Подтверждение регистрации в WAF"
            message = f"Здравствуйте! Для активации вашего аккаунта перейдите по ссылке: {verify_url}"

            send_mail(
                subject,
                message,
                settings.EMAIL_HOST_USER,
                [user.email],
                fail_silently=False,
            )
            return render(request, 'accounts/verify_sent.html', {'email': form.cleaned_data['email']})
    else:
        form = RegistrationForm()
    return render(request, 'accounts/register.html', {'form': form})

@login_required
def dashboard_view(request):
    if user_has_device(request.user) and not request.user.is_verified():
        return redirect('verify_otp_login')
    return render(request, 'accounts/dashboard.html', {'user': request.user})

@login_required
def enable_2fa(request):
    user = request.user
    device, created = TOTPDevice.objects.get_or_create(user=user, name="default")
    
    otp_url = device.config_url
    return render(request, 'accounts/enable_2fa.html', {'otp_url': otp_url})

@login_required
def setup_2fa(request):
    user = request.user
    device, created = TOTPDevice.objects.get_or_create(user=user, name="default")
    
    otp_url = device.config_url
    
    img = qrcode.make(otp_url)
    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    
    qr_code_base64 = base64.b64encode(buffer.getvalue()).decode()
    
    return render(request, 'accounts/setup_2fa.html', {
        'qr_code': qr_code_base64,
        'device': device
    })

@login_required
def verify_2fa_setup(request):
    if request.method == 'POST':
        token = request.POST.get('otp_token')
        user = request.user
        device = TOTPDevice.objects.filter(user=user, name="default").first()
        
        if device and device.verify_token(token):
            device.confirmed = True 
            device.save()
            otp_login(request, device)
            return redirect('dashboard')
        else:
            return render(request, 'accounts/verify_otp.html', {'error': 'Неверный код активации'})    
    return redirect('setup_2fa')

@login_required
def verify_otp_login(request):
    if request.method == 'POST':
        token = request.POST.get('otp_token')
        device = TOTPDevice.objects.filter(user=request.user, confirmed=True).first()
        
        if device and device.verify_token(token):
            from django_otp import login as otp_login
            otp_login(request, device)
            return redirect('dashboard')
        else:
            return render(request, 'accounts/verify_otp.html', {'error': 'Неверный код'})
            
    return render(request, 'accounts/verify_otp.html')