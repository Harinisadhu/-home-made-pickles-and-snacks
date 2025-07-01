from flask import Flask, render_template, request, redirect, url_for

app = Flask(__name__)  # Fixed: __name__ not _name_

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    
    # Dummy check
    if username == 'admin' and password == '123':
        return redirect(url_for('home'))
    else:
        return "Invalid credentials"

@app.route('/home')
def home():
    return render_template('home.html')

@app.route('/shop')
def shop():
    return render_template('shop.html')

@app.route('/cart')
def cart():
    return render_template('cart.html')

@app.route('/buynow')
def buynow():
    return render_template('buynow.html')

@app.route('/feedback')
def feedback():
    return render_template('feedback.html')

@app.route('/thanku')
def thanku():
    return render_template('thanku.html')

if __name__ == '__main__':  # Fixed: __main__ not _main_
    app.run(debug=True)
