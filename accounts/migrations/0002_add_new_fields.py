from django.db import migrations, models
import django.db.models.deletion
import uuid


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0001_initial'),
    ]

    operations = [
        # Add new fields to User
        migrations.AddField(
            model_name='user',
            name='role',
            field=models.CharField(
                choices=[('user', 'Пользователь'), ('admin', 'Администратор')],
                default='user',
                max_length=20,
            ),
        ),
        migrations.AddField(
            model_name='user',
            name='avatar',
            field=models.ImageField(blank=True, null=True, upload_to='avatars/'),
        ),
        migrations.AddField(
            model_name='user',
            name='is_blocked',
            field=models.BooleanField(default=False),
        ),
        # AccessToken
        migrations.CreateModel(
            name='AccessToken',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=100, verbose_name='Название')),
                ('token', models.CharField(default=uuid.uuid4, max_length=64, unique=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('is_active', models.BooleanField(default=True)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='access_tokens', to='accounts.user')),
            ],
            options={'verbose_name': 'Токен доступа', 'verbose_name_plural': 'Токены доступа'},
        ),
        # ProtectedSite
        migrations.CreateModel(
            name='ProtectedSite',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('domain', models.CharField(max_length=255, verbose_name='Домен')),
                ('is_protected', models.BooleanField(default=True, verbose_name='Защита активна')),
                ('traffic_limit_mb', models.IntegerField(default=0, verbose_name='Лимит трафика (МБ)')),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='sites', to='accounts.user')),
            ],
            options={'verbose_name': 'Защищённый сайт', 'verbose_name_plural': 'Защищённые сайты'},
        ),
        # WAFRule
        migrations.CreateModel(
            name='WAFRule',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=200, verbose_name='Название правила')),
                ('pattern', models.TextField(verbose_name='Сигнатура / паттерн')),
                ('description', models.TextField(blank=True, verbose_name='Описание')),
                ('severity', models.CharField(choices=[('low', 'Низкая'), ('medium', 'Средняя'), ('high', 'Высокая'), ('critical', 'Критическая')], default='medium', max_length=20)),
                ('action', models.CharField(choices=[('block', 'Блокировать'), ('allow', 'Разрешить'), ('log', 'Только логировать')], default='block', max_length=20)),
                ('is_active', models.BooleanField(default=True, verbose_name='Активно')),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
            ],
            options={'verbose_name': 'Правило WAF', 'verbose_name_plural': 'Правила WAF'},
        ),
        # RequestLog
        migrations.CreateModel(
            name='RequestLog',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('ip_address', models.GenericIPAddressField()),
                ('method', models.CharField(max_length=10)),
                ('path', models.TextField()),
                ('status_code', models.IntegerField()),
                ('was_blocked', models.BooleanField(default=False)),
                ('timestamp', models.DateTimeField(auto_now_add=True)),
                ('user_agent', models.TextField(blank=True)),
                ('site', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, to='accounts.protectedsite')),
                ('rule_triggered', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, to='accounts.wafrule')),
            ],
            options={'verbose_name': 'Лог запроса', 'verbose_name_plural': 'Логи запросов', 'ordering': ['-timestamp']},
        ),
    ]
