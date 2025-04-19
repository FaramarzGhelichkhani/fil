import os
import django

f = open("/usr/src/app/fil/.env.prod", "r")
row = f.readline()
while row:
    try:
        name, value = row.strip().split("=")
        os.environ[name] = value
    except:
        pass
    row = f.readline()

os.environ['DJANGO_SETTINGS_MODULE'] = 'fil.settings'
os.environ["DJANGO_ALLOW_ASYNC_UNSAFE"] = "true"
django.setup()
