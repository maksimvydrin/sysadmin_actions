import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
logs = pd.read_csv(r"C:\Users\user\Downloads\security_logs_semicolon.csv",sep = ";")

print(logs.head())

incident_rules = {
    "Привилегии":{
        "Ключевые слова": ["sudo","admin rights", "root"],
        "Уровень риска": "Высокий",
        "Рекомендации": [
            "Проверить данные пользователя",
             "Сменить пароль администратора"
        ]
    },

    "Вредоносная активность":{
        "Ключевые слова": ["malicious command","payload", "root"],
        "Уровень риска": "Высокий",
        "Рекомендации": [
            "Проверить запущеннные процессы",
             "Запустить сканирование антивирусом"
        ]
    },

    "Перебор паролей": {
        "Ключевые слова": ["failed login","authentication failed"],
        "Уровень риска": "Средний",
        "Рекомендации": [
            "Проверить пользователя",
             "Сменить пароль пользователя"
        ]
    },

    "Утечка данных": {
        "Ключевые слова": ["outbound traffic","data transfer"],
        "Уровень риска": "Критический",
        "Рекомендации": [
            "Проверить активность",
             "Запретить доступ к файлам",
            "Проверить утечку данных"
        ]
    }
}

def identify_incident(message):
    message = str(message).lower()
    for incident, data in incident_rules.items():
        for keyword in data["Ключевые слова"]:
            if keyword in message:
                return incident

    return "unknown"

logs["incident_type"] = logs["message"].apply(identify_incident)



#разделяем на признаки и на цель
X = logs["message"]
y = logs["incident_type"]

#разделение данных
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

#текст в числовые признаки
vectorizer = TfidfVectorizer()
X_train_vec = vectorizer.fit_transform(X_train)
X_test_vec = vectorizer.transform(X_test)

#обучение
model = RandomForestClassifier()
model.fit(X_train_vec, y_train)

#точность
accuracy = model.score(X_test_vec, y_test)
print("ML model accuracy:", accuracy)

logs.head()


def ml_classify_incident(message):   #предсказание
    message_vec = vectorizer.transform([str(message).lower()])
    prediction = model.predict(message_vec)
    return prediction[0]

logs["ml_incident_type"] = logs["message"].apply(ml_classify_incident) #добавляем столбик с предсказаниями ML


def level_risk(incident):
    if incident in incident_rules:
                return incident_rules[incident]["Уровень риска"]
    return "unknown"


def get_recommendations(incident):
    if incident in incident_rules:
                return incident_rules[incident]["Рекомендации"]
    return "unknown"


logs["risk"] = logs["incident_type"].apply(level_risk)
logs["recommendations"] = logs["incident_type"].apply(get_recommendations)

def show_ci(row):
    print("     Incident     ")
    print("Time:",row["timestamp"])
    print("Host:",row["host"])
    print("User:",row["user"])
    print("Type:",row["incident_type"])
    print("Risk:", row["risk"])
    print("Recommendations", row["recommendations"])

show_ci(logs.iloc[0])

import matplotlib.pyplot as plt
incident_counts = logs["incident_type"].value_counts()
plt.figure()
incident_counts.plot(kind = "bar")
plt.ylabel("Количество")
plt.show()

#пример1
test_log = "multiple failed login attempts detected"

print("log:", test_log)
print("ML prediction:", ml_classify_incident(test_log))

#пример2
test_log = "authentication failed for user"

print("log:", test_log)
print("ML prediction:", ml_classify_incident(test_log))