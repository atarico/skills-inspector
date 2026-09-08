import yaml

with open("config.yml") as f:
    settings = yaml.load(f)

print(settings["profile"])
