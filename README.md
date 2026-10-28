# DASAK-project
# Mini SIEM Dashboard

* Developed by Edgar Palynski, Fredrika Lundqvist Åbrink, Samuel Hörnell, Victoria Lee
## Problem Statement

A lot of cyberattacks occur daily, both on bigger and smaller scales. There is a lot of talk on the best practises on how to prevent them or stop them. However when the cyberattacks occur the first you thing you need to do is to detect it and then working on how to stop it and prevent further damage to the infrastructure. SIEM dashboard is one of such detection technologies.
## References
[Methods and Technologies to Detect Cyber Attacks](https://www.eccu.edu/blog/methods-technologies-detect-cyber-attacks/)
[Best Practices for Creating Effective SIEM Dashboards and Reports - SearchInform](https://searchinform.com/articles/cybersecurity/measures/siem/management/dashboard-and-reporting/)
[Dashboards and reports | SIEM Documentation](https://docs.rapid7.com/insightidr/dashboards-and-reports/)
[How to detect DDoS attacks | TechTarget](https://www.techtarget.com/cybersecurity/tip/How-to-detect-DDoS-attacks)

## Documentation Of Project
### Installation and Running the Project
Install dependencies from the project folder:
```powershell
pip install -r backend/requirements-dev.txt
```

Create a .env file:
Copy `.env.example` to `.env` and set a JWT_SECRET value.

Start the server:
```powershell
cd backend
uvicorn main:app --reload
```

The application is available at http://127.0.0.1:8000/ and the API documentation at http://127.0.0.1:8000/docs.

Run all the tests from the project folder:
```powershell
python -m pytest -v
```

Run only specific tests, such as SQL injection:
```powershell
python -m pytest backend/tests/test_sql_injection.py -v
```

### SQL Injection Detection

SQL injection detection is implemented using regular expressions (regex) to identify common attack patterns, such as OR 1=1 and UNION SELECT. Basic input normalization is also applied to detect patterns that use SQL comments or variations in capitalization and spacing.

The detection is integrated into FastAPI through middleware that inspects URL query parameters and login and registration inputs.

When suspicious input is detected, both a security event and an alert are stored in the database. The event records the activity, while the alert flags it as potentially malicious. The detection is designed for monitoring only. It logs suspicious requests but does not block them.

### XSS Detection

The XSS detection is also implemented using regex to identify potential attacks. Every POST request on the /login and /register page is matched against known XSS patterns. If the contents of a request matches any of these patterns, an Alert is created and shown on the dashboard. 

### DOS Detection
The Dos detection is implemented with the help of event logging functionality and FastAPI middleware which helps register an extra event in the event table of our database. That extra event is called "http_request" which registers every http request made to the server(even if security event was not logged). If there are more than 100 requests in the span of 20 seconds than an alert will be raised by creating one in the alert database. Duplicate alerts are stopped from being created by checking if the last existing DOS alert for that ip is older than 2 minutes. If not then a new alert is not created.

### FastAPI

FastAPI is used to connect the frontend and backend through REST API endpoints. The frontend handles user interactions, while the backend manages authentication, authorization, and database operations.

For example, during login, the frontend sends a request to FastAPI, which validates the user's credentials and returns a response.

### Admin page

The admin page allows authorized administrators to view registered users, including their email addresses and assigned roles.

Authentication is handled using JSON Web Tokens (JWT). After login, users receive a signed token that identifies them. When accessing protected admin endpoints, FastAPI verifies the token and checks whether the user has admin permissions.

Users without the required permissions cannot access protected admin data and are redirected away from the admin page. If a 

To log in on a an account with admin privileges and gain access to the admin page, use the username admin3, and password adminroot. If that account was removed, or you need a new admin account, follow these instructions:

1. Go to http://127.0.0.1:8000/register and follow the instructions on how to create a new account.
2. From the project root, run:

```powershell
sqlite3 dasak.db \
  "UPDATE users SET is_admin = 1 WHERE username = '"username"';"
```
Where "username" should be replaced with username of the account you want to give admin privileges. 

### Authentication

Registration and login are handled through FastAPI. Passwords are hashed with Argon2 before being stored. Login uses JWT tokens, which are checked on every protected request through `get_current_user`, also used by the admin check.

There are three endpoints: `POST /register` creates an account and rejects duplicates, `POST /login` checks the credentials and returns a token (the same error message is shown whether the account does not exist or the password is wrong), and `GET /me` returns the logged in user. The login, registration, and session check pages were connected to these endpoints, so the frontend reflects real login status from the backend.

### SIEM Statistics

An admin only endpoint (`GET /api/stats`) shows total events, successful and failed logins, and events over time, with optional time filtering.

### Brute Force and Password Spraying Detection

Two rules look at login events. One flags an account with 5 or more failed login attempts within 5 minutes. The other flags an IP address that tries 5 or more different accounts within 10 minutes. Detected attacks are saved as alerts, and a duplicate check stops an ongoing attack from creating repeated alerts. Both rules run automatically in the background every 60 seconds through a FastAPI background task, so no manual step is needed to detect an ongoing attack.

### SIEM API

REST API endpoints are implemented to retrieve and manage security events and alerts stored in the database.

The API supports 
- Filtering events by event_type, username, ip_src, and status_code.
- Filtering alerts by rule, status, username, and ip_src.
- Retrieving individual events and alerts.
- Updating alert statuses using a PATCH endpoint.

All endpoints require admin authorization.

### Dashboard

Using the endpoints from the SIEM api and SIEM statistics a count of total amount of alerts and events, aswell as the logs for the events and alerts. The dashboard can be reached on http://127.0.0.1:8000/Dashboard. You need admin privileges to reach the Dashboard. See the paragraph about the Admin Page if you need an account with admin privileges. 

### Event logger and alert creation
Both are implemented in a simillair way where a function exists that can be called to create a certain event or alert and pasted into the database. Events are logged during requests to the website or server and alerts are created when certain rules are triggered.

### Limitations
For SQL injection detection, the detection relies on predefined regex patterns, which means advanced SQL injection attempts may go undetected. False positives may also occur. Therefore, the implementation serves as an additional security monitoring mechanism rather than a complete solution for preventing SQL injection.

## Documentation On Testing The Project
### SQL Injection Detection

Automated tests are implemented using Pytest and FastAPI TestClient to verify the SQL injection detection functionality.

The tests cover:
- Detection of common SQL injection patterns.
- False positives, where harmless input is incorrectly identified as suspicious.
- Detection of SQL injection attempts in HTTP requests.
- Verification that detection does not block requests or change their expected responses.
- Verification that detected attempts are stored as security events and alerts in the database.

### XXS Detection

The test is implemented using Pytest. The test is compromised of a payload containing strings either used in detecting the possiblity of an XSS attack, or strings used to perform an XXS attack.

### Authentication and Login Detection

Automated pytest tests check that the brute force rule triggers at the threshold, does not trigger below it, ignores events outside the time window, and that the password spraying rule works across several accounts.

A separate script (`tests/simulate_brute_force.py`) sends real HTTP requests to a running server, both an attack and normal traffic, to test the whole flow. This found two bugs in the login endpoint, a wrong event type on failed logins and a crash on unknown usernames, which were fixed.

The simulated attack correctly produced an alert, and normal traffic produced no false alarm.

### DoS Simulation
DoS detection is tested using the custom script [simulate_dos_attack.py](backend/tests/simulate_dos_attack.py), which sends repeated HTTP requests to an application endpoint. The event logger records these requests. If too many requests originate from the same IP address, an alert is created in the database with the status `open`.

Several tries were made to simulate DoS attacks, like different number of requests from the same IP address. Also normal amount of traffic was simulated to verify that the rule does not trigger below the threshold. Both by the script and by the user.

These simulations worked as expected according to the implemented rule and created the expected alerts in the database and ignored normal traffic.

### AI usage

Github copilot was used to solve two merge conflicts at the end of the project. The built in github copilot merge conflict solver was used, so no promtp was provided.

## Personal contributions

* Edgar: 
Project architecture, planning and leading.
Basic HTML design and starter pages.
Event logger, alert creation, dos detection rule.
Created and designed the databases.

* Fredrika:
Auth backend (registration, login, JWT) and frontend connection for login, registration and session checking. SIEM statistics. Brute force and password spraying detection with tests and attack simulation.

* Samuel:
Created parts of the database and connected it to the front end. Made the XSS detection and dashboard as well. 

* Victoria:
Implemented the SQL injection detection and automated tests. Connected frontend and backend with FastAPI and created the admin page and its logic. Implemented the SIEM API for security events and alerts.
