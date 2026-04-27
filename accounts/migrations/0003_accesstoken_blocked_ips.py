from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0002_add_new_fields'),
    ]

    operations = [
        migrations.AddField(
            model_name='accesstoken',
            name='blocked_ips',
            field=models.TextField(blank=True, default='', verbose_name='Заблокированные IP'),
        ),
    ]
