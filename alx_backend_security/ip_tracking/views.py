from django.shortcuts import render
from django.http import JsonResponse
from ratelimit.decorators import ratelimit
from django.contrib.auth import authenticate, login
# Create your views here.

# Anonymous users → 5 req/min, Authenticated → 10 req/min
@ratelimit(key='user_or_ip', rate='5/m', method='POST', block=True)
def login_view(request):
    if request.method == "POST":
        username = request.POST.get("username")
        password = request.POST.get("password")

        user = authenticate(request, username=username, password=password)
        if user:
            login(request, user)
            return JsonResponse({"message": "Login successful"})

        return JsonResponse({"error": "Invalid credentials"}, status=400)

    return JsonResponse({"error": "Only POST allowed"}, status=405)

