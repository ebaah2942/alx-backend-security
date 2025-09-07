from .models import RequestLog, BlockedIP
from django.utils.timezone import now
from django.http import HttpResponseForbidden
from django.http import HttpResponseForbidden
from django.utils.timezone import now
from django.core.cache import cache
from django_ip_geolocation.middleware import IpGeolocationMiddleware


class RequestLoggingMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        ip_address = self.get_client_ip(request)

        # Block request if IP is in blacklist
        if BlockedIP.objects.filter(ip_address=ip_address).exists():
            return HttpResponseForbidden("Your IP is blocked.")

        # Try to get cached geolocation (24h = 86400 seconds)
        geo_data = cache.get(f"geo_{ip_address}")
        if not geo_data:
            # Use data injected by django-ip-geolocation
            country = request.META.get("GEOIP_COUNTRY_NAME")
            city = request.META.get("GEOIP_CITY")

            geo_data = {"country": country, "city": city}
            cache.set(f"geo_{ip_address}", geo_data, timeout=86400)

        # Log request with geolocation
        RequestLog.objects.create(
            ip_address=ip_address,
            timestamp=now(),
            path=request.path,
            country=geo_data.get("country"),
            city=geo_data.get("city"),
        )

        return self.get_response(request)

    def get_client_ip(self, request):
        """Extract client IP address from headers."""
        x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
        if x_forwarded_for:
            return x_forwarded_for.split(",")[0].strip()
        return request.META.get("REMOTE_ADDR")