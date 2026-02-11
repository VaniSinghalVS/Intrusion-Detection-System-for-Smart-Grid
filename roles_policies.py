import yaml

def load_policies(path="roles_policies.yaml"):
    with open(path, "r") as f:
        data = yaml.safe_load(f) or {}
    return data.get("roles", {}), data.get("whitelist", {})

def role_of(ip, roles):
    return roles.get(ip, "unknown")

def is_whitelisted(ip, whitelist):
    return ip in set(whitelist.get("control_commands_from", []))
