import pandas as pd

data = []


# WHITELIST
for i in range(120):
    data.append([
        "web-server",
        "user",
        "login",
        "system",
        "user login successful",
        1,  # whitelist
        0,  # blacklist
        "Low",
        "Normal activity"
    ])


# BRUTE FORCE
for i in range(80):
    data.append([
        "auth-server",
        "guest",
        "ssh",
        "auth.log",
        "failed login attempt",
        0,
        1,
        "High",
        "Brute force attack"
    ])

# MALWARE
hosts = ["web-server","db-server","auth-server"]

for host in hosts:
    for i in range(40):
        data.append([
            host,
            "unknown",
            "malware",
            "payload.exe",
            "malicious payload detected",
            0,
            1,
            "High",
            "Malware infection"
        ])


# ADMIN
for i in range(70):
    data.append([
        "db-server",
        "admin",
        "sudo",
        "system",
        "sudo command executed",
        0,
        0,
        "Medium",
        "Privilege escalation"
    ])


columns = [
    "host","user","process","file","message",
    "is_whitelisted","is_blacklisted",
    "threat_level","root_cause"
]

logs = pd.DataFrame(data, columns=columns)

logs.to_csv("security_logs_dataset.csv", sep=";", index=False)

print("Dataset created:", len(logs))