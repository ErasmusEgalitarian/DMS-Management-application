from flask import Flask, jsonify, request, render_template
from flask_cors import CORS
from pymongo import MongoClient
from datetime import datetime, timedelta
import pandas as pd
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Get the absolute path to the templates directory
template_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), 'templates'))
app = Flask(__name__, template_folder=template_dir)
CORS(app)

# MongoDB connection
client = MongoClient(os.getenv('MONGODB_URI', 'mongodb://localhost:27017/'))
db = client['dms_dashboard']

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/users', methods=['GET'])
def get_users():
    users = list(db.users.find({}, {'_id': 0}))
    return jsonify(users)

@app.route('/api/materials', methods=['GET'])
def get_materials():
    materials = list(db.waste_type.find({}, {'_id': 0}))
    return jsonify(materials)

@app.route('/api/stock', methods=['GET'])
def get_stock():
    # Get all measurements
    measurements = list(db.measurements.find({}, {'_id': 0}))
    # Get all sales
    sales = list(db.sales.find({}, {'_id': 0}))
    
    # Calculate current stock for each material
    stock = {}
    for material in db.waste_type.find({}, {'_id': 0}):
        material_id = material['material_id']
        total_measured = sum(m['Weight'] for m in measurements if m['material_id'] == material_id)
        total_sold = sum(s['weight_sold'] for s in sales if s['material_id'] == material_id)
        stock[material_id] = total_measured - total_sold
    
    return jsonify(stock)

@app.route('/api/earnings', methods=['GET'])
def get_earnings():
    # Get last month's earnings
    last_month = datetime.now().replace(day=1) - timedelta(days=1)
    sales = list(db.sales.find({
        'date': {'$gte': last_month}
    }, {'_id': 0}))
    
    total_earnings = sum(sale['price/kg'] * sale['weight_sold'] for sale in sales)
    return jsonify({'total_earnings': total_earnings})

@app.route('/api/earnings-comparison', methods=['GET'])
def get_earnings_comparison():
    # Get earnings for the last 6 months
    six_months_ago = datetime.now() - timedelta(days=180)
    sales = list(db.sales.find({
        'date': {'$gte': six_months_ago}
    }, {'_id': 0}))
    
    if not sales:
        return jsonify({})
    
    # Group by month and material
    df = pd.DataFrame(sales)
    df['month'] = pd.to_datetime(df['date']).dt.strftime('%Y-%m')
    monthly_earnings = df.groupby(['month', 'material_id'])['price/kg'].sum().to_dict()
    
    return jsonify(monthly_earnings)

@app.route('/api/worker-collections', methods=['GET'])
def get_worker_collections():
    # Get collections for the last 30 days
    thirty_days_ago = datetime.now() - timedelta(days=30)
    measurements = list(db.measurements.find({
        'timestamp': {'$gte': thirty_days_ago}
    }, {'_id': 0}))
    
    if not measurements:
        return jsonify({})
    
    # Group by worker and material
    df = pd.DataFrame(measurements)
    worker_collections = df.groupby(['wastepicker_id', 'material_id'])['Weight'].sum().to_dict()
    
    return jsonify(worker_collections)

@app.route('/api/price-fluctuation', methods=['GET'])
def get_price_fluctuation():
    # Get price data for the last 6 weeks
    six_weeks_ago = datetime.now() - timedelta(weeks=6)
    sales = list(db.sales.find({
        'date': {'$gte': six_weeks_ago}
    }, {'_id': 0}))
    
    if not sales:
        return jsonify({})
    
    # Group by week and material
    df = pd.DataFrame(sales)
    df['week'] = pd.to_datetime(df['date']).dt.strftime('%Y-%W')
    price_fluctuation = df.groupby(['week', 'material_id'])['price/kg'].mean().to_dict()
    
    return jsonify(price_fluctuation)

@app.route('/api/birthdays', methods=['GET'])
def get_birthdays():
    # Get current month
    current_month = datetime.now().month
    users = list(db.users.find({
        '$expr': {
            '$eq': [{'$month': '$Birth date'}, current_month]
        }
    }, {'_id': 0}))
    
    return jsonify(users)

@app.route('/test')
def test():
    return "Flask is working correctly!"

@app.route('/test-page')
def test_page():
    with open('test.html', 'r') as f:
        return f.read()

if __name__ == '__main__':
    app.run(debug=True) 