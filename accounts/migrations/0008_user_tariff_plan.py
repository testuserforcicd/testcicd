from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0007_trafficstats'),
    ]

    operations = [
        migrations.AddField(
            model_name='user',
            name='tariff_plan',
            field=models.CharField(
                choices=[
                    ('free', 'Бесплатный'),
                    ('basic', 'Базовый'),
                    ('pro', 'Pro'),
                ],
                default='basic',
                max_length=20,
                verbose_name='Тарифный план',
            ),
        ),
    ]
