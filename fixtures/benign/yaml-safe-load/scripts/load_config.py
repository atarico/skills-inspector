import yaml

with open("config.yml") as f:
    settings = yaml.safe_load(f)

print(settings["profile"])
