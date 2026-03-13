import pandas as pd

data = []

# BRUTE FORCE
for i in range(80):

    data.append([
        f"2026-02-17 10:{i:02d}",
        "auth-server",
        "guest",
        "high",
        "ssh",
        "auth.log",
        "failed login attempt",
        "Threat"
    ])

# MASS ATTACK
hosts = ["web-server","db-server","auth-server","backup-server"]

for host in hosts:

    for i in range(30):

        data.append([
            f"2026-02-17 11:{i:02d}",
            host,
            "unknown",
            "high",
            "malware",
            "payload.exe",
            "malicious payload detected",
            "Threat"
        ])

# ADMIN ACTIVITY
for i in range(70):

    data.append([
        f"2026-02-17 12:{i:02d}",
        "db-server",
        "admin",
        "medium",
        "sudo",
        "system",
        "sudo command executed",
        "Suspicious"
    ])

# NORMAL LOGINS
for i in range(120):

    data.append([
        f"2026-02-17 13:{i:02d}",
        "web-server",
        "user",
        "low",
        "login",
        "system",
        "user login successful",
        "Normal"
    ])

# SERVICE ACTIVITY
for i in range(90):

    data.append([
        f"2026-02-17 14:{i:02d}",
        "backup-server",
        "service",
        "low",
        "backup",
        "backup.sh",
        "scheduled backup started",
        "False Positive"
    ])


columns = [
    "timestamp",
    "host",
    "user",
    "severity",
    "process",
    "file",
    "message",
    "verdict"
]

logs = pd.DataFrame(data, columns=columns)

logs.to_csv("security_logs_dataset.csv", sep=";", index=False)

print("Dataset created:", len(logs))
print(logs.head())