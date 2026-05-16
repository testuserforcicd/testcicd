from django.db import models
from django.contrib.auth.models import AbstractUser
import uuid


class User(AbstractUser):
    ROLE_USER = 'user'
    ROLE_ADMIN = 'admin'
    ROLE_CHOICES = [
        (ROLE_USER, 'Пользователь'),
        (ROLE_ADMIN, 'Администратор'),
    ]

    TARIFF_FREE = 'free'
    TARIFF_BASIC = 'basic'
    TARIFF_PRO = 'pro'
    TARIFF_CHOICES = [
        (TARIFF_FREE, 'Бесплатный'),
        (TARIFF_BASIC, 'Базовый'),
        (TARIFF_PRO, 'Pro'),
    ]

    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default=ROLE_USER)
    tariff_plan = models.CharField(max_length=20, choices=TARIFF_CHOICES, default=TARIFF_BASIC, verbose_name='Тарифный план')
    is_email_verified = models.BooleanField(default=False)
    email_verification_token = models.CharField(max_length=100, blank=True, null=True)
    avatar = models.ImageField(upload_to='avatars/', blank=True, null=True)
    is_blocked = models.BooleanField(default=False)

    def is_admin_role(self):
        return self.role == self.ROLE_ADMIN or self.is_superuser


class AccessToken(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='access_tokens')
    name = models.CharField(max_length=100, verbose_name='Название')
    token = models.CharField(max_length=64, unique=True, default=uuid.uuid4)
    created_at = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(default=True)
    # Список IP-адресов, заблокированных для этого токена (через запятую)
    blocked_ips = models.TextField(blank=True, default='', verbose_name='Заблокированные IP')

    def get_blocked_ips_list(self):
        return [ip.strip() for ip in self.blocked_ips.split(',') if ip.strip()]

    def __str__(self):
        return f"{self.name} ({self.user.username})"

    class Meta:
        verbose_name = 'Токен доступа'
        verbose_name_plural = 'Токены доступа'


class ProtectedSite(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='sites')
    domain = models.CharField(max_length=255, verbose_name='Домен')
    #target_ip = models.GenericIPAddressField(verbose_name='IP-адрес сервера', default='127.0.0.1')
    target_ip = models.CharField(max_length=100)

    is_protected = models.BooleanField(default=True, verbose_name='Защита активна')
    traffic_limit_mb = models.IntegerField(default=0, verbose_name='Лимит трафика (МБ, 0=без лимита)')
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.domain} ({self.user.username})"

    class Meta:
        verbose_name = 'Защищённый сайт'
        verbose_name_plural = 'Защищённые сайты'

class TrafficStats(models.Model):
    """Статистика трафика по дням"""
    site = models.ForeignKey(ProtectedSite, on_delete=models.CASCADE, related_name='traffic_stats')
    date = models.DateField(auto_now_add=True)
    bytes_in = models.BigIntegerField(default=0, verbose_name='Входящий трафик (байт)')
    bytes_out = models.BigIntegerField(default=0, verbose_name='Исходящий трафик (байт)')
    
    class Meta:
        unique_together = ('site', 'date')
        verbose_name = 'Статистика трафика'
        verbose_name_plural = 'Статистика трафика'
        ordering = ['-date']
    
    @property
    def total_mb(self):
        return (self.bytes_in + self.bytes_out) / (1024 * 1024)
    
    def __str__(self):
        return f"{self.site.domain} - {self.date}: {self.total_mb:.2f} MB"

class WAFRule(models.Model):
    SEVERITY_CHOICES = [
        ('low', 'Низкая'),
        ('medium', 'Средняя'),
        ('high', 'Высокая'),
        ('critical', 'Критическая'),
    ]
    ACTION_CHOICES = [
        ('block', 'Блокировать'),
        ('allow', 'Разрешить'),
        ('log', 'Только логировать'),
    ]

    name = models.CharField(max_length=200, verbose_name='Название правила')
    pattern = models.TextField(verbose_name='Сигнатура / паттерн')
    description = models.TextField(blank=True, verbose_name='Описание')
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES, default='medium')
    action = models.CharField(max_length=20, choices=ACTION_CHOICES, default='block')
    is_active = models.BooleanField(default=True, verbose_name='Активно')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.name

    class Meta:
        verbose_name = 'Правило WAF'
        verbose_name_plural = 'Правила WAF'


class RequestLog(models.Model):
    site = models.ForeignKey(ProtectedSite, on_delete=models.SET_NULL, null=True, blank=True)
    ip_address = models.GenericIPAddressField()
    method = models.CharField(max_length=10)
    path = models.TextField()
    status_code = models.IntegerField()
    was_blocked = models.BooleanField(default=False)
    rule_triggered = models.ForeignKey(WAFRule, on_delete=models.SET_NULL, null=True, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    user_agent = models.TextField(blank=True)

    def __str__(self):
        return f"{self.ip_address} -> {self.path} [{self.status_code}]"

    class Meta:
        verbose_name = 'Лог запроса'
        verbose_name_plural = 'Логи запросов'
        ordering = ['-timestamp']

class AttackAttempt(models.Model):
    """Отслеживание подозрительных запросов для автоматического бана"""
    site = models.ForeignKey(ProtectedSite, on_delete=models.CASCADE, related_name='attack_attempts')
    ip_address = models.GenericIPAddressField()
    rule_triggered = models.ForeignKey(WAFRule, on_delete=models.SET_NULL, null=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        indexes = [
            models.Index(fields=['site', 'ip_address', 'timestamp']),
        ]
        verbose_name = 'Попытка атаки'
        verbose_name_plural = 'Попытки атак'
    
    def __str__(self):
        return f"{self.ip_address} - {self.rule_triggered.name if self.rule_triggered else 'Unknown'} at {self.timestamp}"

class BannedIP(models.Model):
    """Забаненные IP-адреса с автоматическим управлением"""
    site = models.ForeignKey(ProtectedSite, on_delete=models.CASCADE, related_name='banned_ips')
    ip_address = models.GenericIPAddressField()
    reason = models.TextField()
    banned_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    is_active = models.BooleanField(default=True)
    attack_count = models.IntegerField(default=0, help_text="Количество атак перед баном")
    time_window_minutes = models.IntegerField(default=10, help_text="Временное окно в минутах")
    
    class Meta:
        unique_together = ('site', 'ip_address')
        indexes = [
            models.Index(fields=['site', 'ip_address', 'is_active', 'expires_at']),
        ]
        verbose_name = 'Забаненный IP'
        verbose_name_plural = 'Забаненные IP'
    
    def __str__(self):
        return f"{self.ip_address} on {self.site.domain} - Banned until {self.expires_at}"
    
    @property
    def is_expired(self):
        from django.utils import timezone
        return timezone.now() > self.expires_at
        
        
class AdminMessage(models.Model):
    """Сообщения пользователей администратору"""
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='admin_messages')
    message = models.TextField(verbose_name='Сообщение')
    created_at = models.DateTimeField(auto_now_add=True)
    is_read = models.BooleanField(default=False)

    def __str__(self):
        return f"Сообщение от {self.user.username} ({self.created_at.strftime('%d.m.Y')})"

    class Meta:
        verbose_name = 'Сообщение администратору'
        verbose_name_plural = 'Сообщения администратору'
        ordering = ['-created_at']
