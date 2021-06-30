import base64
from django.shortcuts import render
from user.apiClasses import User
from user.apiClasses import Project

currentUser = User()
project = Project()


# helper functions
def convertBase64():
    with open('pic.png', 'rb') as myfile:
        encoded_str = base64.b64encode(myfile.read())
    print(encoded_str)

    return encoded_str


def decodeBase64(encoded_str):
    with open('mypic.png', 'wb') as myfile:
        myfile.write(base64.b64decode(encoded_str))


# Create your views here.
def index(request):
    return render(request, 'index.html')


def signup(request):
    return currentUser.signup(request=request)


def login(request):
    return currentUser.login(request=request)


def getUserInfo(request, uid):
    return currentUser.getUserInfo(request, uid)


def updateSI(request, uid, item):
    return currentUser.updateSI(request, uid, item)


def update(request, uid):
    return currentUser.update(request=request, uid=uid)


def deleteAccount(request, uid):
    return currentUser.deleteAccount(request, uid)


def delete(request, uid, key):
    return currentUser.delete(request, uid, key)


def createProject(request, uid):
    return project.createProject(request, uid)


def deleteProject(request, pid):
    return project.deleteProject(request, pid)


def getProjects(request, uid):
    return project.getProjects(request, uid)


def getProject(request, pid):
    return project.getProject(request, pid)


def getAllProjects(request):
    return project.getAllProjects(request)


def updateProject(request, pid):
    return project.upadateProject(request, pid)
