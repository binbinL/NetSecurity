import json
import pickle
import DataShuffle
from flask import Flask, request, render_template, jsonify, flash, redirect, url_for

app = Flask(__name__)


# return render_template('result.html', result_json=json.dumps(result))

@app.route('/', methods=['GET', 'POST'])
def result():
    if request.method == 'GET':  # get请求，直接返回页面
        return render_template('index.html')

    if request.method == "POST":
        data = request.form.get('data')  # 获取数据
        X_test = DataShuffle.convert(data)  # 对数据进行处理
        if type(X_test) == str:  # 正常返回的是df类型，如果数据有误，返回'error',其为字符串类型
            return json.dumps({"code": 400, "msg": "Invalid Input"})
        else:
            loaded_model = pickle.load(open("shuffle1.dat", "rb"))  # 加载model
            rates = loaded_model.predict_proba(X_test)  # 预测
            result = DataShuffle.getTopN(8, rates)  # 获取概率值前八的概率大小
            return json.dumps({"code": 200, "data": result})  # 返回json类结果


if __name__ == '__main__':
    app.config["SECRET_KEY"] = 'TPmi4aLWRbyVq8zu9v82dWYW1'
    app.run(debug=True)
