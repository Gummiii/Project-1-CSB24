# A03:2021 Injection (SQL Injection): The application uses unsanitized user input in a SQL query, allowing an attacker to manipulate the query to access or modify data in the database which is not the intended way.

from django.db import connection
from django.http import HttpResponse

def vulnerable_sql(request):
    username = request.GET.get('username', '')
    query = f"SELECT * FROM app_user WHERE username = '{username}'"  # This is where the SQL injection occurs
    cursor = connection.cursor()
    cursor.execute(query)
    user = cursor.fetchone()
    return HttpResponse(f"User: {user}")



            ### SOLUTION ###
### (Uncomment below for safe code) ###


# from app.models import User
# def secure_sql(request):
#     username = request.GET.get('username', '')
#     user = User.objects.filter(username=username).first()
#     return HttpResponse(f"User: {user}")





# A01:2021 Broken Access Control: The application does not properly enforce access control restrictions on authenticated users, allowing attackers to view sensitive information or perform unauthorized actions.


def view_user_data(request, user_id):
    # Directly fetch user without validation
    user = User.objects.get(id=user_id)  # This is where the broken access control occurs
    return HttpResponse(f"Hello, {user.username}")
    
    
    
            ### SOLUTION ###
### (Uncomment below for safe code) ###


# def secure_user_data(request, user_id):
#     if request.user.id != int(user_id):
#         return HttpResponse("Access Denied!", status=403)
#     user = User.objects.get(id=user_id)
#     return HttpResponse(f"Hello, {user.username}")
