from flask import Flask, request,render_template
from main import Incident,predict_incident,engine

app = Flask(__name__) #создаем объект приложения
@app.route("/")  #получаем страницу
def index():
    return render_template("forms.html") #подключаем html
@app.route("/predict",methods = ["POST"]) #отправка данных
def predict():
    host = request.form.get("host")
    user = request.form.get("user")
    process = request.form.get("process")
    file = request.form.get("file")
    message = request.form.get("message")

    incident= Incident(host,user,process,file,message)

    threat,root = predict_incident(incident)

    recs = engine.evaluate(incident)

    return render_template(
        "incident.html",
        threat = threat,
        root = root,
        recommendation = recs,
        incident=incident
    )

if __name__ == "__main__":
    app.run(debug=True)