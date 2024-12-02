from django.urls import path 
from user import views

urlpatterns = [
    path('register_user/', views.register_user, name='register_user'),
    path('login_user/', views.login_user, name='login_user'),
    path('logout_user/', views.logout_user, name='logout_user'),
    path('create-switch/', views.create_switch, name='create_switch'),
    path('update-switch/', views.update_switch, name='update_switch'),
    path('action-switch/', views.action_switch, name='action_switch'),
    path('get_data/', views.get_data, name='get_data'),
    path('delete_switch/', views.delete_switch, name='delete_switch'),
    path('compare_token/', views.compare_token, name='compare_token'),
    path('save_wifi/', views.save_wifi_credential, name='save_wifi_credential'),
    path('switch/<str:switchname>/', views.read_switch, name='read_switch'),
    path('all-switches/', views.list_all_switches, name='list_all_switches'),  # New endpoint to list all switches
    path('gethomeappliancesfrontend/', views.gethomeappliancesfrontend, name='gethomeappliancesfrontend'),  # New endpoint to list all switches   
]
