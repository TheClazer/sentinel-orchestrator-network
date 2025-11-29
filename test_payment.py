import urllib.request

try:
    with urllib.request.urlopen("http://localhost:3001/docs") as response:
        print(f"Payment Service Status: {response.getcode()}")
except Exception as e:
    print(f"Payment Service Check Failed: {e}")
