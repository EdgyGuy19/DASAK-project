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

### FastAPI

FastAPI is used to connect frontend and backend with API endpoints.

### Admin page

The admin page is created so that admins can see all registered users, their emails and what roles they have. The authorization is checked with FastAPI. Without admin authorization, the user will be redirected from the admin page.

### SIEM API

REST API endpoints were implemented to get security events and alerts from the database. It supports event filtering by event_type, username, ip_src, status_code and alert filtering by rule, status, username, ip_src. It is also possible to get individual events and alerts and update the alert status. The API requires admin authorization.

## Documentation On Testing The Project
### SQL Injection Detection
Automated testing is implemented with Pytest and FastAPI TestClient to check the SQL injection detection.

It tests:
- Identifying common SQL injection patterns.
- If normal user input can be falsely identified as SQL injection (false positive).
- Detection of SQL injection in HTTP requests.
- Checks that the detection doesn't block normal HTTP requests.
- Checks that detections are registered as events and alerts in the database.


## Personal contributions

* Edgar: 
Project architecture, planning and leading.
Event logger, alert creation, dos detection rule.
Created and designed the databases.

* Fredrika:

* Samuel:

* Victoria:
Implemented the SQL injection detection and automated tests. Connected frontend and backend with FastAPI and created the admin page and its logic. Implemented the SIEM API for security events and alerts.