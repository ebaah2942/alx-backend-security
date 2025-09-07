from .models import RequestLog
from django.utils.timezone import now

class RequestLoggingMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Get client IP address
        ip_address = self.get_client_ip(request)
        # Save log to database
        RequestLog.objects.create(
            ip_address=ip_address,
            timestamp=now(),
            path=request.path
        )
        # Continue processing
        response = self.get_response(request)
        return response

    def get_client_ip(self, request):
        """Extract client IP address from request headers."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]  # First IP in list
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip
