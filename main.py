import pandas as pd
import numpy as np

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score

# 1. Загрузка датасета

logs = pd.read_csv("security_logs_dataset.csv", sep=";")

print("Dataset size:", len(logs))

# 2. Feature Engineering

severity_map = {"low":0,"medium":1,"high":2}

logs["severity_num"] = logs["severity"].map(severity_map)

# частота событий
event_frequency = logs["message"].value_counts()
logs["event_freq"] = logs["message"].map(event_frequency)

# активность пользователя
user_activity = logs["user"].value_counts()
logs["user_activity"] = logs["user"].map(user_activity)

# распространение файла по системам
host_spread = logs.groupby("file")["host"].nunique()
logs["host_spread"] = logs["file"].map(host_spread)

# 3. TF-IDF преобразование текста

vectorizer = TfidfVectorizer()

X_text = vectorizer.fit_transform(logs["message"])

# 4. Дополнительные признаки

X_features = logs[[
    "severity_num",
    "event_freq",
    "user_activity",
    "host_spread"
]]

# объединяем признаки
X = np.hstack((X_text.toarray(), X_features.values))

y = logs["verdict"]

# 5. Обучение ML модели

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

model = RandomForestClassifier()

model.fit(X_train, y_train)

y_pred = model.predict(X_test)

accuracy = accuracy_score(y_test, y_pred)

print("ML accuracy:", accuracy)

# 6. Класс Incident

class Incident:

    def __init__(self, timestamp, host, user, severity, process, file, message):

        self.timestamp = timestamp
        self.host = host
        self.user = user
        self.severity = severity
        self.process = process
        self.file = file
        self.message = message

# 7. ML prediction функция

def ml_predict(incident):

    message_vec = vectorizer.transform([incident.message]).toarray()

    severity_num = severity_map[incident.severity]

    event_freq = event_frequency.get(incident.message, 1)

    user_act = user_activity.get(incident.user, 1)

    spread = host_spread.get(incident.file, 1)

    features = np.array([[severity_num, event_freq, user_act, spread]])

    X_input = np.hstack((message_vec, features))

    return model.predict(X_input)[0]

# 8. Rule Engine

class Rule:

    def __init__(self, name, condition, recommendation):

        self.name = name
        self.condition = condition
        self.recommendation = recommendation


class RuleEngine:

    def __init__(self, rules):

        self.rules = rules

    def evaluate(self, incident):

        recommendations = []

        for rule in self.rules:

            if rule.condition(incident):

                recommendations.append(rule.recommendation)

        if not recommendations:
            recommendations.append("Требуется дополнительный анализ")

        return recommendations

# 9. Правила системы

rule1 = Rule(
    "Brute force attack",
    lambda i: "failed login" in i.message,
    "Проверить попытки входа и заблокировать IP"
)

rule2 = Rule(
    "Privilege escalation",
    lambda i: "sudo" in i.message,
    "Проверить действия администратора"
)

rule3 = Rule(
    "Service activity",
    lambda i: i.user == "service",
    "Проверить корректность сервисного процесса"
)

rule4 = Rule(
    "Malware spread",
    lambda i: i.file == "payload.exe", "Проверить систему на наличие вредоносного ПО"
)

engine = RuleEngine([rule1, rule2, rule3, rule4])

# 10. Демонстрация работы

incident = Incident(
    "2026-02-17",
    "auth-server",
    "guest",
    "high",
    "ssh",
    "auth.log",
    "failed login attempt"
)

ml_verdict = ml_predict(incident)

recommendations = engine.evaluate(incident)

print("\nIncident detected")
print("Host:", incident.host)
print("User:", incident.user)
print("Message:", incident.message)

print("\nML verdict:", ml_verdict)

print("\nRecommendations:")

for r in recommendations:
    print("-", r)