import os
import uuid
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash
from werkzeug.security import generate_password_hash, check_password_hash
import boto3
from botocore.exceptions import ClientError

# ------------------------------------------------------------------------------
# Flask setup
# ------------------------------------------------------------------------------
app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "1q2w3e4r5t6y")  # Use env-var for production

# ------------------------------------------------------------------------------
# AWS setup
# ------------------------------------------------------------------------------
AWS_REGION = os.getenv('AWS_REGION', 'ap-south-1')
USER_TABLE_NAME = os.getenv('USER_TABLE_NAME', 'HomePicklesUsers')
FEEDBACK_TABLE_NAME = os.getenv('FEEDBACK_TABLE_NAME', 'HomePicklesFeedback')
SNS_ORDER_TOPIC_ARN = os.getenv('SNS_ORDER_TOPIC_ARN')  # Required
SNS_FEEDBACK_TOPIC_ARN = os.getenv('SNS_FEEDBACK_TOPIC_ARN')  # Required

dynamodb = boto3.resource('dynamodb', region_name=AWS_REGION)
sns = boto3.client('sns', region_name=AWS_REGION)
ec2 = boto3.client('ec2', region_name=AWS_REGION)

# ------------------------------------------------------------------------------
# Session cart init
# ------------------------------------------------------------------------------
@app.before_request
def init_session():
    session.setdefault('cart', [])
    session.setdefault('user', None)

# ------------------------------------------------------------------------------
# Routes
# ------------------------------------------------------------------------------

@app.route('/')
@app.route('/home')
def home():
    return render_template('index.html')

@app.route('/shop')
def shop():
    return render_template('shop.html')

@app.route('/cart')
def cart():
    return render_template('cart.html', cart=session.get('cart', []))

@app.route('/add_to_cart', methods=['POST'])
def add_to_cart():
    data = request.form
    name = data.get('name')
    price = int(data.get('price'))
    image = data.get('image')

    cart = session.get('cart', [])
    for item in cart:
        if item['name'] == name:
            item['quantity'] += 1
            break
    else:
        cart.append({'name': name, 'price': price, 'image': image, 'quantity': 1})

    session['cart'] = cart
    flash(f"{name} added to cart", "success")
    return redirect(url_for('shop'))

@app.route('/remove_from_cart', methods=['POST'])
def remove_from_cart():
    name = request.form.get('name')
    cart = session.get('cart', [])
    session['cart'] = [item for item in cart if item['name'] != name]
    return redirect(url_for('cart'))

@app.route('/buynow')
def buynow():
    try:
        sns.publish(
            TopicArn=SNS_ORDER_TOPIC_ARN,
            Subject="New Home Pickles Order",
            Message="A new order has been placed via the Home Pickles website."
        )
    except ClientError as e:
        app.logger.error("SNS Order Publish Failed: %s", e)
    session['cart'] = []
    return render_template('buynow.html')

@app.route('/feedback')
def feedback():
    return render_template('feedback.html')

@app.route('/thanku', methods=['POST', 'GET'])
def thanku():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        message = request.form.get('message')

        try:
            fb_tbl = dynamodb.Table(FEEDBACK_TABLE_NAME)
            fb_tbl.put_item(Item={
                'id': str(uuid.uuid4()),
                'name': name,
                'email': email,
                'message': message
            })

            sns.publish(
                TopicArn=SNS_FEEDBACK_TOPIC_ARN,
                Subject="New Home Pickles Feedback",
                Message=f"Name: {name}\nEmail: {email}\n\n{message}"
            )
        except ClientError as e:
            app.logger.error("Feedback SNS or DynamoDB failed: %s", e)

    return render_template('thanku.html')

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    try:
        user_tbl = dynamodb.Table(USER_TABLE_NAME)
        resp = user_tbl.get_item(Key={'username': username})
        user = resp.get('Item')
        if user and check_password_hash(user['password'], password):
            session['user'] = username
            return redirect(url_for('home'))
        else:
            flash('Invalid credentials', 'danger')
            return redirect(url_for('home'))
    except ClientError as e:
        return f"Login error: {e.response['Error']['Message']}", 500

@app.route('/signup', methods=['POST'])
def signup():
    username = request.form.get('username')
    email = request.form.get('email')
    password = generate_password_hash(request.form.get('password'))
    try:
        user_tbl = dynamodb.Table(USER_TABLE_NAME)
        user_tbl.put_item(
            Item={'username': username, 'email': email, 'password': password},
            ConditionExpression='attribute_not_exists(username)'
        )
        flash('Registration successful. Please login.', 'success')
        return redirect(url_for('home'))
    except ClientError as e:
        if e.response['Error']['Code'] == 'ConditionalCheckFailedException':
            return "Username already exists", 409
        return f"Signup failed: {e.response['Error']['Message']}", 500

@app.route('/ec2-info')
def ec2_info():
    try:
        data = ec2.describe_instances()
        instances = [
            {
                'InstanceId': i['InstanceId'],
                'State': i['State']['Name'],
                'Type': i['InstanceType'],
                'PublicIP': i.get('PublicIpAddress', 'N/A')
            }
            for r in data['Reservations'] for i in r['Instances']
        ]
        return jsonify(instances)
    except ClientError as e:
        return f"EC2 error: {e.response['Error']['Message']}", 500

# ------------------------------------------------------------------------------
# Run server
# ------------------------------------------------------------------------------
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.getenv('PORT', 5000)), debug=True)
