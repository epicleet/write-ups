from flask import Flask, render_template, request, url_for, redirect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import re, subprocess, uuid, os

app = Flask(__name__, static_url_path='/static', static_folder='static')

limiter = Limiter(
	app,
	key_func=get_remote_address
)

@app.route('/', methods=["GET","POST"])
def root():
	if request.method == "POST" :
		f = request.files["dots"]
		filename = str(uuid.uuid4())
		f.save(os.path.join("/tmp/",filename))
		asciidots_output = subprocess.run(["asciidots","/tmp/"+filename],capture_output=True)
		os.remove("/tmp/"+filename)
		return asciidots_output.stdout
	else :
		return render_template('index.html')

if __name__ == '__main__':
	app.run(host='0.0.0.0')

