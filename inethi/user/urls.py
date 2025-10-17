"""
URL Configuration for user API
"""
from django.urls import path
from . import views

app_name = 'user'

urlpatterns = [
    path(
        'users/<int:id>/',
        views.RetrieveUserView.as_view(),
        name="retrieve-user"
    ),
    path(
        'network-admin/login/',
        views.NetworkAdminLoginView.as_view(),
        name='network-admin-login'
    ),
    path('search/', views.UserSearchView.as_view(), name='search'),
    path('create/', views.CreateUserView.as_view(), name='create'),
    path('token/', views.CreateTokenView.as_view(), name='token'),
    path('me/', views.ManageUserView.as_view(), name='me'),
    path('refresh/', views.RefreshTokenView.as_view(), name='refresh-token'),
    # Admin endpoints
    path(
        'admin/users/',
        views.AdminUserListView.as_view(),
        name='admin-users-list'
    ),
    path(
        'admin/users/<int:pk>/',
        views.AdminUserDetailView.as_view(),
        name='admin-users-detail'
    ),
    path(
        'admin/users/<int:pk>/update/',
        views.AdminUserUpdateView.as_view(),
        name='admin-users-update'
    ),
]
