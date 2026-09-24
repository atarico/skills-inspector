# Container build

Run the following to build the image:

```dockerfile
FROM node:20-slim
RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*
```
