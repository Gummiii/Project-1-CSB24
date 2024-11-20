from django.shortcuts import render
from django.db import connection
from django.http import HttpResponse
from app.models import User
from django.contrib.auth.decorators import login_required
from app.models import InsecureUser
from app.models import SecureUser
from django.http import JsonResponse


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
        return HttpResponse(f"User: {username}, {user},<br>Correct User should be testuser, test@example.com, password123<br>Now try change the URL to /vulnerable_sql?username=testuser' OR '1'='1")

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


# A02:2021 Cryptographic Failures: The application uses weak or insecure cryptographic algorithms to protect sensitive data.

def register_insecure_user(request):
    username = request.GET.get('username', '')
    email = request.GET.get('email', '')
    password = request.GET.get('password', '')

    if not (username and email and password):
        return HttpResponse("Missing required fields", status=400)
    
    user = InsecureUser.objects.create(username=username, email=email, password=password)  # This is where the cryptographic failure occurs
    return HttpResponse(f"User {user.username} registered with plaintext password {user.password}")


def register_secure_user(request):
    username = request.GET.get('username', '')
    email = request.GET.get('email', '')
    password = request.GET.get('password', '')

    if not (username and email and password):
        return HttpResponse("Missing required fields", status=400)
    user = SecureUser(username=username, email=email)
    user.set_password(password)
    user.save()

    return HttpResponse(f"User {user.username} registered securely!")  

def view_passwords(request):
    insecure_users = InsecureUser.objects.all()
    secure_users = SecureUser.objects.all()

    data = {
        "insecure_users": [
            {"username": user.username, "password": user.password,} for user in insecure_users
        ],
        "secure_users": [
            {"username": user.username, "password": user.password} for user in secure_users
        ]
    }
    return JsonResponse(data)




# A10:2021 Server-Side Request Forgery (SSRF): The application allows attackers to make arbitrary requests on behalf of the server, potentially exposing internal services to the internet.


import requests

def fetch_url(request):
    url = request.GET.get('url', '')
    response = requests.get(url)  # This is where the SSRF occurs
    return HttpResponse(response.text)



            ### SOLUTION ###



from urllib.parse import urlparse
from ipaddress import ip_address, ip_network



def secure_fetch_url(request):
    url = request.GET.get('url', '')
    if not url:
        return HttpResponse("No URL provided", status=400)

    try:
        # Parse the URL
        parsed_url = urlparse(url)

        # Validate scheme
        if parsed_url.scheme not in ['http', 'https']:
            return HttpResponse("Invalid URL scheme", status=400)

        # Resolve the hostname to an IP address
        import socket
        resolved_ip = socket.gethostbyname(parsed_url.hostname)

        # Define private IP ranges
        private_ip_ranges = [
            ip_network('127.0.0.0/8'),  # Loopback
            ip_network('10.0.0.0/8'),  # Private network
            ip_network('172.16.0.0/12'),  # Private network
            ip_network('192.168.0.0/16'),  # Private network
            ip_network('169.254.0.0/16'),  # Link-local
        ]

        # Check if the resolved IP belongs to a private range
        ip_obj = ip_address(resolved_ip)
        if any(ip_obj in net for net in private_ip_ranges):
            return HttpResponse("Access to private IP ranges is not allowed", status=403)

        # Fetch the URL content if validation passes
        response = requests.get(url, timeout=5)  # Add a timeout to prevent hanging
        return HttpResponse(response.text)

    except socket.gaierror:
        return HttpResponse("Invalid hostname", status=400)

    except requests.exceptions.RequestException as e:
        return HttpResponse(f"Error fetching the URL: {str(e)}", status=500)

    except Exception as e:
        return HttpResponse(f"Unexpected error: {str(e)}", status=500)


