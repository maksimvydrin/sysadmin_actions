import pandas as pd
import numpy as np

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score

# 1. Загрузка данных

logs = pd.read_csv("security_logs_dataset.csv", sep=";")

#print("Dataset size:", len(logs))

# 2. Feature Engineering

# частота событий
event_freq = logs["message"].value_counts()
logs["event_freq"] = logs["message"].map(event_freq)

# активность пользователя
user_activity = logs["user"].value_counts()
logs["user_activity"] = logs["user"].map(user_activity)

# распространение файла
host_spread = logs.groupby("file")["host"].nunique()
logs["host_spread"] = logs["file"].map(host_spread)

# 3. TF-IDF

vectorizer = TfidfVectorizer()

X_text = vectorizer.fit_transform(logs["message"])

# 4. Признаки

X_features = logs[[
    "event_freq",
    "user_activity",
    "host_spread",
    "is_whitelisted",
    "is_blacklisted"
]]

X = np.hstack((X_text.toarray(), X_features.values))

# 5. Две ML модели

# модель 1 — уровень угрозы
y_threat = logs["threat_level"]

# модель 2 — причина
y_root = logs["root_cause"]


X_train, X_test, y1_train, y1_test = train_test_split(
    X, y_threat, test_size=0.2, random_state=42
)

_, _, y2_train, y2_test = train_test_split(
    X, y_root, test_size=0.2, random_state=42
)


model_threat = RandomForestClassifier()
model_root = RandomForestClassifier()

model_threat.fit(X_train, y1_train)
model_root.fit(X_train, y2_train)

# 6. Оценка моделей

pred1 = model_threat.predict(X_test)
pred2 = model_root.predict(X_test)

#print("Threat accuracy:", accuracy_score(y1_test, pred1))
#print("Root cause accuracy:", accuracy_score(y2_test, pred2))

# 7. Incident класс

class Incident:

    def __init__(self, host, user, process, file, message):

        self.host = host
        self.user = user
        self.process = process
        self.file = file
        self.message = message

# 8. ML prediction

def predict_incident(incident):

    message_vec = vectorizer.transform([incident.message]).toarray()

    freq = event_freq.get(incident.message, 1)
    user_act = user_activity.get(incident.user, 1)
    spread = host_spread.get(incident.file, 1)

    # whitelist / blacklist логика
    is_white = 1 if incident.user in ["user", "service"] else 0
    is_black = 1 if "payload" in incident.file or "failed" in incident.message else 0

    features = np.array([[freq, user_act, spread, is_white, is_black]])

    X_input = np.hstack((message_vec, features))

    threat = model_threat.predict(X_input)[0]
    root = model_root.predict(X_input)[0]

    return threat, root

# 9. Rule Engine (рекомендации)

class Rule:

    def __init__(self, name, condition, recommendation):
        self.name = name
        self.condition = condition
        self.recommendation = recommendation


class RuleEngine:

    def __init__(self, rules):
        self.rules = rules

    def evaluate(self, incident):

        recs = []

        for rule in self.rules:
            if rule.condition(incident):
                recs.append(rule.recommendation)

        if not recs:
            recs.append("Требуется анализ")

        return recs


# правила

rules = [

    Rule(
        "Brute force",
        lambda i: "failed login" in i.message,
        "Заблокировать IP и проверить попытки входа"
    ),

    Rule(
        "Malware",lambda i: "payload" in i.file,
        "Изолировать хост и проверить систему"
    ),

    Rule(
        "Admin activity",
        lambda i: "sudo" in i.message,
        "Проверить действия администратора"
    )
]

engine = RuleEngine(rules)

# # 10. Демонстрация
#
# incident = Incident(
#     "auth-server",
#     "guest",
#     "ssh",
#     "auth.log",
#     "failed login attempt"
# )
#
# threat, root = predict_incident(incident)
#
# recommendations = engine.evaluate(incident)

# print("\nIncident:")
# print("Host:", incident.host)
# print("User:", incident.user)
# print("Message:", incident.message)
#
# print("\nThreat level:", threat)
# print("Root cause:", root)
#
# print("\nRecommendations:")
# for r in recommendations:
#     print("-", r)
