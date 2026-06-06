from flask import Flask, render_template, request
import pandas as pd
from main import Incident, predict_incident, engine

app = Flask(__name__)

# ---------- Функции для получения уникальных значений из датасета ----------
def get_unique_values(column_name):
    try:
        df = pd.read_csv("security_logs_dataset.csv", sep=";")
        # Убираем NaN и дубликаты, сортируем
        values = sorted(df[column_name].dropna().unique().tolist())
        return values
    except Exception as e:
        print(f"Ошибка загрузки колонки {column_name}: {e}")
        return []

# ---------- Маршруты ----------
@app.route("/")
def index():
    # Получаем все возможные варианты для каждого поля
    users = get_unique_values("user")
    hosts = get_unique_values("host")
    processes = get_unique_values("process")
    files = get_unique_values("file")
    # Сообщения (message) обычно уникальны, но можно тоже загрузить
    messages = get_unique_values("message")
    
    return render_template("forms.html",
                           users=users,
                           hosts=hosts,
                           processes=processes,
                           files=files,
                           messages=messages)

@app.route("/predict", methods=["POST"])
def predict():
    # Данные приходят из обычной формы (заполненной вручную или через модальное окно)
    host = request.form.get("host")
    user = request.form.get("user")
    process = request.form.get("process")
    file = request.form.get("file")
    message = request.form.get("message")
    
    incident = Incident(host, user, process, file, message)
    threat, root = predict_incident(incident)
    recs = engine.evaluate(incident)
    
    return render_template("incident.html",
                           threat=threat,
                           root=root,
                           recs=recs,
                           incident=incident)

if __name__ == "__main__":
    app.run(debug=True)