from django.urls import path
from . import views

urlpatterns = [
    path('', views.index, name="index function"),
    path('signup', views.signup, name="user signup"),
    path('login', views.login, name="user login"),
    path('getUserInfo/<str:uid>', views.getUserInfo, name="get user info by uid"),
    path('update/<str:uid>/<str:item>', views.updateSI, name="update skills or interests by uid"),
    path('update/<str:uid>', views.update, name="update user info by uid"),
    path('delete/<str:uid>/<str:key>', views.delete, name="delete user info by uid"),
    path('deleteAccount/<str:uid>', views.deleteAccount, name="delete user account by uid"),
    path('getAllProjects', views.getAllProjects, name="get all projects"),
    path('createProject/<str:uid>', views.createProject, name="create new project"),
    path('deleteProject/<str:pid>', views.deleteProject, name="delete project from DB"),
    path('getProjects/<str:uid>', views.getProjects, name="get all projects of a user"),
    path('getProject/<str:pid>', views.getProject, name="get project by pid"),
    path('updateProject/<str:pid>', views.updateProject, name="update project by pid")
]
