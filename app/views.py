from django.shortcuts import render
from django.db import connection
from django.http import HttpResponse
from app.models import User
from django.contrib.auth.decorators import login_required
def index(request):
    return render(request, 'index.html')   # This is the default homepage view


def login_view(request):
    return HttpResponse("Login page")  # This is the login page


# A03:2021 Injection (SQL Injection): The application uses unsanitized user input in a SQL query, allowing an attacker to manipulate the query to access or modify data in the database which is not the intended way.



def vulnerable_sql(request):
    username = request.GET.get('username', '')
    query = f"SELECT * FROM app_user WHERE username = '{username}'"  # This is where the SQL injection occurs
    print(f"Executing query: {query}")    
    cursor = connection.cursor()
    cursor.execute(query)
    user = cursor.fetchone()
    print(f"Query result: {user}")
    print(f"Try change the URL to /vulnerable_sql?username=testuser' OR '1'='1 for the SQL Injection")
    if user:
        return HttpResponse(f"User: {user},<br>Correct User should be testuser, test@example.com, password123<br>Now try change the URL to /vulnerable_sql?username=testuser' OR '1'='1")

    else:
        return HttpResponse("User not found")
    
    


            ### SOLUTION ###



def secure_sql(request):
    username = request.GET.get('username', '')
    try:
        # ORM-based query instead of a raw SQL
        user = User.objects.get(username=username)
        return HttpResponse(f"User: {user.username}, Email: {user.email}, Password: {user.password}<br>Now try again with /secure_sql?username=testuser' OR '1'='1 for the SQL Injection")
    except User.DoesNotExist:
        return HttpResponse("User not found.")





# A01:2021 Broken Access Control: The application does not properly enforce access control restrictions on authenticated users, allowing attackers to view sensitive information or perform unauthorized actions.
#Login as admin with so we are user_id=2

def view_user_data(request, user_id):
    # Directly fetch user without validation
    try:
        user = User.objects.get(id=user_id)  # This is where the broken access control occurs
        return HttpResponse(f"User: {user.username}, Email: {user.email},<br><br>Now try again with /view_user_data/1 for the Broken Access Control")
    except User.DoesNotExist:
        return HttpResponse("User not found.")
    
    
    
            ### SOLUTION ###





@login_required
def secure_view_user_data(request, user_id):
    # Ensure the logged-in user owns the data
    if request.user.id != user_id:
        return HttpResponse("<h1>Access Denied!</h1><br><br> Since we are only a user called admin with user_id=2, we now can't access user_id=1", status=403)  # Forbidden

    try:
        user = User.objects.get(id=user_id)
        return HttpResponse(f"User: {user.username}, Email: {user.email}")
    except User.DoesNotExist:
        return HttpResponse("User not found.")





# A10:2021 Server-Side Request Forgery (SSRF): The application allows attackers to make arbitrary requests on behalf of the server, potentially exposing internal services to the internet.


import requests

def fetch_url(request):
    url = request.GET.get('url', '')
    response = requests.get(url)  # This is where the SSRF occurs
    return HttpResponse(response.text)



            ### SOLUTION ###
### (Uncomment below for safe code) ###


# from urllib.parse import urlparse
# def secure_fetch_url(request):
#     url = request.GET.get('url', '')
#     parsed_url = urlparse(url)
#     if parsed_url.scheme not in ['http', 'https']:
#         return HttpResponse("Invalid URL", status=400)
#     response = requests.get(url)
#     return HttpResponse(response.text)