# A03:2021 Injection (SQL Injection): The application uses unsanitized user input in a SQL query, allowing an attacker to manipulate the query to access or modify data in the database which is not the intended way.

from django.db import connection
from django.http import HttpResponse

def vulnerable_sql(request):
    username = request.GET.get('username', '')
    query = f"SELECT * FROM app_user WHERE username = '{username}'"  # UNSAFE!
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

