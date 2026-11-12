from django.http import HttpResponse, HttpResponseRedirect
from django.db import connection
from django.db.models.expressions import RawSQL
from django.utils.safestring import mark_safe
from django.views import View
from myapp.models import User
cursor = connection.cursor()

def view(request):
    from django.utils.html import escape
    return HttpResponse("<h1>" + escape(request.GET["x"]) + "</h1>")
