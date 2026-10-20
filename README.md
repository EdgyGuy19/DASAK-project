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

The SQL injection detection is implemented with regex to identify basic attack patterns such as OR 1=1 and UNION SELECT. The detection is integrated into FastAPI through middleware that controls the query parameters and user input. If there is suspicious input, it will be registered as an event and an alert in the database. This only logs detections, there is no prevention of the attacks.

### DOS Detection
The Dos detection is implemented with the help of event logging functionality and FastAPI middleware which helps register an extra event in the event table of our database. That extra event is called "http_request" which registers every http request made to the server(even if security event was not logged). If there are more than 30 requests in the span of 20 seconds than an alert will be raised by creating one in the alert database. Duplicate alerts are stopped from being created by checking if the last existing DOS alert for that ip is older than 2 minutes. If not then a new alert is not created.

### FastAPI

FastAPI is used to connect frontend and backend with API endpoints.

### Admin page

The admin page is created so that admins can see all registered users, their emails and what roles they have. The authorization is checked with FastAPI. Without admin authorization, the user will be redirected from the admin page.

### Authentication

Registration and login are handled through FastAPI. Passwords are hashed with Argon2 before being stored. Login uses JWT tokens, which are checked on every protected request through `get_current_user`, also used by the admin check.

There are three endpoints: `POST /register` creates an account and rejects duplicates, `POST /login` checks the credentials and returns a token (the same error message is shown whether the account does not exist or the password is wrong), and `GET /me` returns the logged in user. The login, registration, and session check pages were connected to these endpoints, so the frontend reflects real login status from the backend.

### SIEM Statistics

An admin only endpoint (`GET /api/stats`) shows total events, successful and failed logins, and events over time, with optional time filtering.

### Brute Force and Password Spraying Detection

Two rules look at login events. One flags an account with 5 or more failed login attempts within 5 minutes. The other flags an IP address that tries 5 or more different accounts within 10 minutes. Detected attacks are saved as alerts, and a duplicate check stops an ongoing attack from creating repeated alerts. Both rules run automatically in the background every 60 seconds through a FastAPI background task, so no manual step is needed to detect an ongoing attack.

### SIEM API

REST API endpoints were implemented to get security events and alerts from the database. It supports event filtering by event_type, username, ip_src, status_code and alert filtering by rule, status, username, ip_src. It is also possible to get individual events and alerts and update the alert status. The API requires admin authorization.

### Event logger and alert creation
Both are implemented in a simillair way where a function exists that can be called to create a certain event or alert and pasted into the database. Events are logged during requests to the website or server and alerts are created when certain rules are triggered.

## Documentation On Testing The Project
### SQL Injection Detection
Automated testing is implemented with Pytest and FastAPI TestClient to check the SQL injection detection.

It tests:
- Identifying common SQL injection patterns.
- If normal user input can be falsely identified as SQL injection (false positive).
- Detection of SQL injection in HTTP requests.
- Checks that the detection doesn't block normal HTTP requests.
- Checks that detections are registered as events and alerts in the database.

### Authentication and Login Detection

Automated pytest tests check that the brute force rule triggers at the threshold, does not trigger below it, ignores events outside the time window, and that the password spraying rule works across several accounts.

A separate script (`tests/simulate_brute_force.py`) sends real HTTP requests to a running server, both an attack and normal traffic, to test the whole flow. This found two bugs in the login endpoint, a wrong event type on failed logins and a crash on unknown usernames, which were fixed.

The simulated attack correctly produced an alert, and normal traffic produced no false alarm.

### DoS Simulation
DoS detection is tested using the custom script [simulate_dos_attack.py](backend/tests/simulate_dos_attack.py), which sends repeated HTTP requests to an application endpoint. The event logger records these requests. If too many requests originate from the same IP address, an alert is created in the database with the status `open`.

Several tries were made to simulate DoS attacks, like different number of requests from the same IP address. Also normal amount of traffic was simulated to verify that the rule does not trigger below the threshold. Both by the script and by the user.

These simulations worked as expected according to the implemented rule and created the expected alerts in the database and ignored normal traffic.

## Personal contributions

* Edgar: 
Project architecture, planning and leading.
Basic HTML design and starter pages.
Event logger, alert creation, dos detection rule.
Created and designed the databases.

* Fredrika:
Auth backend (registration, login, JWT) and frontend connection for login, registration and session checking. SIEM statistics. Brute force and password spraying detection with tests and attack simulation.

* Samuel:

* Victoria:
Implemented the SQL injection detection and automated tests. Connected frontend and backend with FastAPI and created the admin page and its logic. Implemented the SIEM API for security events and alerts.
