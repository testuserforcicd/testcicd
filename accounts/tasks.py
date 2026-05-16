import csv
import os
from celery import shared_task
from django.conf import settings
from django.utils import timezone
from .models import RequestLog

@shared_task
def export_logs_to_csv(user_id, is_admin=False):
    filename = f"logs_{user_id}_{timezone.now().strftime('%Y%m%d_%H%M%S')}.csv"
    file_path = os.path.join(settings.MEDIA_ROOT, 'exports', filename)
    
    os.makedirs(os.path.dirname(file_path), exist_ok=True)

    if is_admin:
        queryset = RequestLog.objects.all()
    else:
        queryset = RequestLog.objects.filter(site__user_id=user_id)
    
    logs = queryset.values_list(
        'timestamp', 'site__domain', 'ip_address', 'method', 
        'path', 'status_code', 'was_blocked', 'rule_triggered__name'
    ).iterator(chunk_size=10000)

    with open(file_path, 'w', encoding='utf-8-sig') as f:
        writer = csv.writer(f, delimiter=';')
        writer.writerow(['Время', 'Сайт', 'IP', 'Метод', 'Путь', 'Статус', 'Заблокирован', 'Правило'])
        
        for log in logs:
            writer.writerow([
                log[0].strftime('%Y-%m-%d %H:%M:%S'),
                log[1] or '—',
                log[2],
                log[3],
                log[4],
                log[5],
                'Да' if log[6] else 'Нет',
                log[7] or '—'
            ])
            
    return f"/media/exports/{filename}" 