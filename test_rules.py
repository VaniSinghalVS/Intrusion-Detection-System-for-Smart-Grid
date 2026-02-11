# test_rules.py
from rules_engine import detect_replay, detect_unauth_command
import time

# test replay using fake feature (same details repeated)
feat = {"src":"10.0.0.5","dst":"10.0.0.3","details":"CMD:READ"}
print("replay1:", detect_replay(feat))
time.sleep(1)
print("replay2:", detect_replay(feat))
time.sleep(1)
print("replay3:", detect_replay(feat))  # should become True at this call

# test unauthorized command
roles = {"10.0.0.5":"meter", "10.0.0.3":"control"}
whitelist = {"control_commands_from":["10.0.0.3"], "sensitive_commands":["RESET","OPEN_VALVE"], "allowed_command_types":{"control":["START","STOP"], "meter":["READ"]}}
feat_cmd = {"src":"10.0.0.5","command":"RESET"}
print("unauth_cmd:", detect_unauth_command(feat_cmd, roles, whitelist))  # should be True
