from django.urls import path

from .views import AuthCsrfView, MeView

urlpatterns = [
    path("me/", MeView.as_view(), name="me"),
    path("auth/csrf/", AuthCsrfView.as_view(), name="auth-csrf"),
]