from django.http import HttpResponse, HttpResponseRedirect
from django.db import connection
from django.db.models.expressions import RawSQL
from django.utils.safestring import mark_safe
from django.views import View
from myapp.models import User
cursor = connection.cursor()

def view(request):
    uid = request.get_full_path()
    cursor.execute("SELECT * FROM u WHERE id=" + uid)
