import time
import jwt
from datetime import datetime, timedelta
from mybackend.settings import SECRET_KEY
import bcrypt
from pymongo import MongoClient
import json
from django.http import JsonResponse
from bson import ObjectId

# DB
client = MongoClient()
db = client['project-portal']
userCollection = db['users']
projectCollection = db['projects']

wrong_http_call = {'status': False, 'message': 'Wrong HTTP call'}
QUERY_LIMIT = 10


def decode_token(auth_token):
    try:
        payload = jwt.decode(auth_token, SECRET_KEY, algorithms=['HS256'])
        return {'status': True, 'message': payload['sub']}
    except jwt.ExpiredSignatureError:
        return {'status': False, 'message': 'Signature expired. Please log in again.'}
    except jwt.InvalidTokenError:
        return {'status': False, 'message': 'Invalid token. Please log in again'}


def create_token(userid):
    try:
        payload = {
            'exp': datetime.now() + timedelta(days=1),
            'iat': datetime.now(),
            'sub': userid
        }
        return (
            jwt.encode(
                payload,
                SECRET_KEY,
                algorithm='HS256'
            ),
            payload['exp']
        )
    except Exception as e:
        return e


def get_hashed_pswd(plain_pswd):
    return bcrypt.hashpw(plain_pswd, bcrypt.gensalt())


def check_pswd(plain_pswd, hashed_pswd):
    return bcrypt.checkpw(plain_pswd, hashed_pswd)


def authorize(request):
    if 'Authorization' not in request.headers:
        return {'status': False, 'message': 'auth token missing'}

    # print(request.headers['Authorization'])
    auth_token = request.headers['Authorization'].split(' ')[1]
    # print(auth_token)
    auth_res = decode_token(auth_token)
    if not auth_res['status']:
        return auth_res

    return {'status': True, 'message': 'Authorized'}


def checkRequest(request, pid):
    auth = authorize(request)
    if not auth['status']:
        return auth, 401

    if len(pid) != 24:
        return {'status': False, 'message': 'invalid ID'}, 400

    return {'status': True, 'message': 'correct'}, 200


def getProjectList(skip_freq):
    projects = []
    for project in projectCollection.find().sort([('createdAt', -1)]).limit(QUERY_LIMIT).skip(QUERY_LIMIT*skip_freq):
        # project['_id'] = str(project['_id'])
        project['pid'] = str(project['_id'])
        del project['_id']
        # print(str(type(project['createdAt'])))
        if isinstance(project['createdAt'], datetime):
            project['createdAt'] = project['createdAt'].strftime("%d %b %Y %-I:%M %p")
        projects.append(project)
    
    # print(projects, type(projects))
    return projects


class User:

    def signup(self, request):
        if request.method == 'POST':

            if not bool(request.body):
                return JsonResponse({'status': False, 'message': 'empty request body, No data found'}, status=204)
            data = json.loads(request.body.decode('utf-8'))
            user = userCollection.find_one({'mis': data['mis']})
            if user:
                return JsonResponse({'status': False, 'message': 'This MIS already exists'}, status=409)

            # hash pswd and save in db
            data['pswd'] = get_hashed_pswd(data['pswd'].encode('utf-8'))
            # add additional fields
            data['createdAt'] = str(datetime.now())
            data['branch'] = 'Electrical'
            data['yearOfStudy'] = 'FY'
            data['projects'] = []
            data['skills'] = []
            data['interests'] = []
            data['gender'] = ''
            data['profilePic'] = ''
            data['email'] = ''

            # print(data)
            uid = userCollection.insert_one(data).inserted_id
            return JsonResponse({'status': True, 'message': 'User added successfully', 'uid': str(uid)}, status=201)

        return JsonResponse(wrong_http_call, status=405)

    def login(self, request):
        if request.method == 'POST':
            if not bool(request.body):
                return JsonResponse({'status': False, 'message': 'empty request body, No data found'}, status=204)
            data = json.loads(request.body.decode('utf-8'))
            user = userCollection.find_one({'mis': data['mis']})

            if not user:
                return JsonResponse({'status': False, 'message': 'User not found'}, status=404)
            password = data['pswd'].encode('utf-8')
            res = check_pswd(password, user['pswd'])

            if not res:
                return JsonResponse({'status': False, 'message': 'Wrong password'}, status=403)

            token, exp = create_token(str(user['_id']))
            return JsonResponse({'status': True, 'message': 'successfully logged in',
                                 'data': {
                                     'token': token, 'tokenExpiry': str(exp),
                                     'name': user['name'], 'uid': str(user['_id'])
                                 }})

        return JsonResponse(wrong_http_call, status=405)

    def getUserInfo(self, request, uid):
        if request.method == 'GET':
            check, code = checkRequest(request, uid)
            print(check, code)
            if code != 200:
                return JsonResponse(check, status=code)

            user = userCollection.find_one({'_id': ObjectId(uid)}, {'pswd': False})
            if not user:
                return JsonResponse({'status': False, 'message': 'User not found'}, status=404)

            # user['_id'] = str(user['_id'])
            user['uid'] = str(user['_id'])
            del user['_id']
            return JsonResponse({'status': True, 'message': 'User found', 'user': user})

        return JsonResponse(wrong_http_call, status=405)

    def update(self, request, uid):
        if request.method == 'PUT':
            check, code = checkRequest(request, uid)
            print(check, code)
            if code != 200:
                return JsonResponse(check, status=code)

            user = userCollection.find_one({'_id': ObjectId(uid)})
            if not user:
                return JsonResponse({'status': False, 'message': 'User not found'}, status=404)

            data = json.loads(request.body.decode('utf-8'))

            userCollection.update_one({'_id': ObjectId(uid)}, {
                '$set': data
            })
            return JsonResponse({'status': True, 'message': 'Updated successfully'})

        return JsonResponse(wrong_http_call, status=405)

    def updateSI(self, request, uid, item):
        if request.method == 'PUT':
            auth = authorize(request)
            if not auth['status']:
                return JsonResponse(auth, status=401)
            data = json.loads(request.body.decode('utf-8'))
            if item == 'skills' or item == 'interests':
                print(item)
                userCollection.update_one({'_id': ObjectId(uid)}, {
                    '$set': {item: data[item]}
                })
                return JsonResponse({'status': True, 'message': 'added '+item+' successfully'})
            else:
                return JsonResponse({'status': False, 'message': 'Invalid Item to update'}, status=400)
        return JsonResponse(wrong_http_call, status=405)

    def delete(self, request, uid, key):
        if request.method == 'DELETE':
            check, code = checkRequest(request, uid)
            print(check, code)
            if code != 200:
                return JsonResponse(check, status=code)

            # user = userCollection.find_one({'_id': ObjectId(uid)})
            # if not user:
            #     return JsonResponse({'status': False, 'message': 'User not found'}, status=404)
            #
            # data = json.loads(request.body.decode('utf-8'))
            # key = list(data.keys())

            userCollection.update_one({'_id': ObjectId(uid)}, {
                '$set': {key: ''}
            })
            return JsonResponse({'status': True, 'message': 'Deleted successfully'})

        return JsonResponse(wrong_http_call, status=405)

    def deleteAccount(self, request, uid):
        if request.method == 'DELETE':
            check, code = checkRequest(request, uid)
            print(check, code)
            if code != 200:
                return JsonResponse(check, status=code)

            # delete account permanently and all associated projects
            user = userCollection.find_one({'_id': ObjectId(uid)})
            if not user:
                return JsonResponse({'status': False, 'message': 'User not found'}, status=404)

            print(len(user['projects']))
            # delete all projects of this user
            for pid in user['projects']:
                print(pid)
                projectCollection.delete_one({'_id': ObjectId(pid)})

            userCollection.delete_one({'_id': ObjectId(uid)})

            return JsonResponse({'status': True, 'message': 'Account deleted successfully'})

        return JsonResponse(wrong_http_call, status=405)


class Project:

    def createProject(self, request, uid):
        if request.method == 'POST':
            auth = authorize(request)
            if not auth['status']:
                return JsonResponse(auth, status=401)

            if not bool(request.body):
                return JsonResponse({'status': False, 'message': 'empty request body, No data found'}, status=204)

            data = json.loads(request.body.decode('utf-8'))
            if len(uid) != 24:
                return JsonResponse({'status': False, 'message': 'invalid user ID'}, status=400)
            user = userCollection.find_one({'_id': ObjectId(uid)})
            if not user:
                return JsonResponse({'status': False, 'message': 'User not found'}, status=404)

            data['author'] = uid
            # data['createdAt'] = time.strftime("%d %b %Y %-I:%M %p")
            data['createdAt'] = datetime.utcnow()+timedelta(hours=5, minutes=30)
            data['authorName'] = user['name']
            print(data)
            pid = projectCollection.insert_one(data).inserted_id

            # add this project to author's projects array
            userCollection.update_one({'_id': ObjectId(uid)}, {'$push': {'projects': str(pid)}})

            return JsonResponse({'status': True, 'message': 'project created', 'pid': str(pid)}, status=201)

        return JsonResponse(wrong_http_call, status=405)

    def deleteProject(self, request, pid):
        if request.method == 'DELETE':

            project = projectCollection.find_one({'_id': ObjectId(pid)})
            if not project:
                return JsonResponse({'status': False, 'message': 'project not found'}, status=404)

            # delete this project from author's projects array
            userCollection.update_one({'_id': ObjectId(project['author'])}, {
                '$pull': {'projects': pid}
            })

            projectCollection.delete_one({'_id': ObjectId(pid)})

            return JsonResponse({'status': True, 'message': 'Deleted successfully'})

        return JsonResponse(wrong_http_call, status=405)

    def getAllProjects(self, request):
        if request.method == 'GET':
            auth = authorize(request)
            print(auth)
            if not auth['status']:
                return JsonResponse(auth, status=401)

            skip_freq = int(request.GET['freq'])
            print(skip_freq)
            projects = getProjectList(skip_freq)

            return JsonResponse({'status': True, 'message': 'got all projects', 'projects': projects})

        return JsonResponse(wrong_http_call, status=405)

    def getProjects(self, request, uid):
        if request.method == 'GET':

            check, code = checkRequest(request, uid)
            print(check, code)
            if code != 200:
                return JsonResponse(check, status=code)

            userProjects = []
            for prj in projectCollection.find({'author': uid}):
                # prj['_id'] = str(prj['_id'])
                prj['pid'] = str(prj['_id'])
                del prj['_id']
                if isinstance(prj['createdAt'], datetime):
                    prj['createdAt'] = prj['createdAt'].strftime("%d %b %Y %-I:%M %p")
                userProjects.append(prj)

            return JsonResponse({'status': True, 'message': 'Got projects for this user', 'projects': userProjects})

        return JsonResponse(wrong_http_call, status=405)

    def getProject(self, request, pid):
        if request.method == 'GET':

            check, code = checkRequest(request, pid)
            print(check, code)
            if code != 200:
                return JsonResponse(check, status=code)

            prj = projectCollection.find_one({'_id': ObjectId(pid)})

            if not prj:
                return JsonResponse({'status': False, 'message': 'Project not found'}, status=404)

            prj['pid'] = str(prj['_id'])
            del prj['_id']
            prj['createdAt'] = prj['createdAt'].strftime("%d %b %Y %-I:%M %p")

            return JsonResponse({'status': True, 'message': 'Project found', 'project': prj})

        return JsonResponse(wrong_http_call, status=405)

    def upadateProject(self, request, pid):
        if request.method == 'PUT':
            check, code = checkRequest(request, pid)
            print(check, code)
            if code != 200:
                return JsonResponse(check, status=code)

            data = json.loads(request.body.decode('utf-8'))

            if not projectCollection.find_one({'_id': ObjectId(pid)}):
                return JsonResponse({'status': False, 'message': 'Project not found'}, status=404)

            projectCollection.update_one({'_id': ObjectId(pid)}, {'$set': data})
            return JsonResponse({'status': True, 'message': 'Updated successfully'})

        return JsonResponse(wrong_http_call, status=405)