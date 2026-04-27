from django import forms
from django.contrib.auth import get_user_model
from django.contrib.auth.forms import PasswordChangeForm
from .models import User, ProtectedSite

User = get_user_model()


class RegistrationForm(forms.Form):
    username = forms.CharField(max_length=100, label="Имя пользователя")
    email = forms.EmailField(label="Email")
    password = forms.CharField(widget=forms.PasswordInput, label="Пароль")
    password2 = forms.CharField(widget=forms.PasswordInput, label="Подтверждение пароля")

    def clean(self):
        cleaned_data = super().clean()
        p1 = cleaned_data.get('password')
        p2 = cleaned_data.get('password2')
        if p1 and p2 and p1 != p2:
            raise forms.ValidationError("Пароли не совпадают")
        return cleaned_data


class AvatarForm(forms.ModelForm):
    class Meta:
        model = User
        fields = ['avatar']


class ChangeRoleForm(forms.ModelForm):
    class Meta:
        model = User
        fields = ['role']


class ProtectedSiteForm(forms.ModelForm):
    class Meta:
        model = ProtectedSite
        fields = ['domain', 'target_ip', 'traffic_limit_mb']
        labels = {
            'domain': 'Домен сайта (например, mysite.com)',
            'target_ip': 'IP-адрес сервера (куда отправлять трафик)',
            'traffic_limit_mb': 'Лимит трафика (МБ, 0=без лимита)'
        }
        widgets = {
            'domain': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'mysite.com'}),
            'target_ip': forms.TextInput(attrs={'class': 'form-control', 'placeholder': '192.168.1.5'}),
        }
        
class AccessTokenForm(forms.Form):
    name = forms.CharField(max_length=100, label="Название токена")


class WAFRuleForm(forms.Form):
    name = forms.CharField(max_length=200, label="Название")
    pattern = forms.CharField(widget=forms.Textarea(attrs={'rows': 3}), label="Сигнатура / паттерн")
    description = forms.CharField(widget=forms.Textarea(attrs={'rows': 2}), required=False, label="Описание")
    severity = forms.ChoiceField(choices=[
        ('low', 'Низкая'), ('medium', 'Средняя'), ('high', 'Высокая'), ('critical', 'Критическая')
    ], label="Критичность")
    action = forms.ChoiceField(choices=[
        ('block', 'Блокировать'), ('allow', 'Разрешить'), ('log', 'Только логировать')
    ], label="Действие")
    is_active = forms.BooleanField(required=False, initial=True, label="Активно")
