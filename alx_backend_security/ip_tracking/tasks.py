from celery import shared_task
from django.utils.timezone import now, timedelta
from django.db.models import Count
from .models import RequestLog, SuspiciousIP

SENSITIVE_PATHS = ["/admin", "/login"]

@shared_task
def detect_anomalies():
    one_hour_ago = now() - timedelta(hours=1)

    # 1. Flag IPs with more than 100 requests/hour
    heavy_users = (
        RequestLog.objects.filter(timestamp__gte=one_hour_ago)
        .values("ip_address")
        .annotate(request_count=Count("id"))
        .filter(request_count__gt=100)
    )

    for entry in heavy_users:
        ip = entry["ip_address"]
        reason = f"Excessive requests: {entry['request_count']} in the last hour"
        SuspiciousIP.objects.get_or_create(ip_address=ip, reason=reason)

    # 2. Flag IPs accessing sensitive paths
    sensitive_logs = RequestLog.objects.filter(
        timestamp__gte=one_hour_ago, path__in=SENSITIVE_PATHS
    )

    for log in sensitive_logs:
        reason = f"Accessed sensitive path: {log.path}"
        SuspiciousIP.objects.get_or_create(ip_address=log.ip_address, reason=reason)
