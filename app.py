from flask import Flask, jsonify, request, render_template, redirect, url_for, flash, session
from flask_cors import CORS
from pymongo import MongoClient
from datetime import datetime, timedelta
import pandas as pd
import os
from dotenv import load_dotenv
from apscheduler.schedulers.background import BackgroundScheduler
from functools import wraps
import bcrypt
import secrets
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from bson.objectid import ObjectId

# Load environment variables
load_dotenv()

# Get the absolute path to the templates directory
template_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), 'templates'))
app = Flask(__name__, template_folder=template_dir)
CORS(app)

# Set a strong secret key for session management
app.secret_key = os.getenv('SECRET_KEY', secrets.token_hex(32))

# Set up rate limiter
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# MongoDB connection
client = MongoClient(os.getenv('MONGODB_URI', 'mongodb://localhost:27017/'))
db = client['DMS']

# Create a material ID to name mapping
def get_material_mapping():
    materials = list(db.waste_type.find({}, {'_id': 0}))
    material_mapping = {}
    for material in materials:
        material_id = material.get('material_id', '')
        material_name = material.get('material', f'Material {material_id}')
        # Store both string and integer versions of the ID
        material_mapping[str(material_id)] = material_name
        material_mapping[material_id] = material_name
    return material_mapping

# Add this function after the get_material_mapping function
def update_worker_contributions():
    # Get current period
    current_date = datetime.now()
    current_month = current_date.month
    current_year = current_date.year
    
    # Get all workers
    workers = list(db.users.find({'user_type': {'$in': [1, 2]}}))
    
    # Get all materials
    materials = list(db.materials.find())
    
    # Get all sales for the current period
    sales = list(db.sales.find({
        'date': {
            '$gte': datetime(current_year, current_month, 1),
            '$lt': datetime(current_year, current_month + 1, 1) if current_month < 12 else datetime(current_year + 1, 1, 1)
        }
    }))
    
    # Initialize contributions dictionary
    contributions = {}
    
    # Process each sale
    for sale in sales:
        material_id = sale['material_id']
        wastepicker_id = sale.get('wastepicker_id')
        
        if not wastepicker_id:
            continue
            
        key = (wastepicker_id, material_id)
        if key not in contributions:
            contributions[key] = {
                'weight': 0,
                'earnings': 0
            }
            
        contributions[key]['weight'] += sale['weight_sold']
        contributions[key]['earnings'] += sale['weight_sold'] * sale['price/kg']
    
    # Update worker_contributions collection
    for (wastepicker_id, material_id), data in contributions.items():
        db.worker_contributions.update_one(
            {
                'wastepicker_id': wastepicker_id,
                'material_id': material_id,
                'period': {
                    'month': current_month,
                    'year': current_year
                }
            },
            {
                '$set': {
                    'weight': data['weight'],
                    'earnings': data['earnings']
                }
            },
            upsert=True
        )

# Add a new route to trigger the update manually (for testing)
@app.route('/api/update-worker-contributions', methods=['POST'])
def trigger_update_worker_contributions():
    update_worker_contributions()
    return jsonify({"status": "success", "message": "Worker contributions updated"})

# Create a scheduler
scheduler = BackgroundScheduler()
scheduler.add_job(func=update_worker_contributions, trigger="cron", hour=0, minute=0)
scheduler.start()

# Initialize worker contributions on startup
print("Initializing worker contributions...")
update_worker_contributions()

# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            flash('Por favor, faça login para acessar o painel.', 'warning')
            return redirect(url_for('login'))
        if session['user'].get('user_type') != 0:
            flash('Acesso negado. Apenas administradores podem acessar o painel.', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Function to hash passwords
def hash_password(password):
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    # Convert to string for MongoDB storage
    return hashed.decode('utf-8')

# Function to verify passwords
def verify_password(password, hashed_password):
    # If hashed_password is None or empty, return False
    if not hashed_password:
        return False
        
    # If hashed_password is already bytes, use it directly
    if isinstance(hashed_password, bytes):
        try:
            return bcrypt.checkpw(password.encode('utf-8'), hashed_password)
        except ValueError:
            # If there's an error with the hash format, return False
            return False
            
    # If hashed_password is a string, try to decode it properly
    if isinstance(hashed_password, str):
        try:
            # Try to decode from base64 if it's stored that way
            import base64
            decoded = base64.b64decode(hashed_password)
            return bcrypt.checkpw(password.encode('utf-8'), decoded)
        except:
            # If decoding fails, try encoding directly
            try:
                return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))
            except:
                return False
    
    # If we get here, something unexpected happened
    return False

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    if request.method == 'POST':
        cpf = request.form.get('cpf')
        password = request.form.get('password')
        remember = request.form.get('remember') == 'on'
        
        # Find user by CPF
        user = db.users.find_one({'CPF': cpf})
        
        if user and verify_password(password, user.get('password', b'')):
            if user.get('user_type') == 0:  # Admin user
                session['user'] = {
                    'cpf': user['CPF'],
                    'name': user['full_name'],
                    'user_type': user['user_type']
                }
                
                # Set session to permanent if remember me is checked
                if remember:
                    session.permanent = True
                    app.permanent_session_lifetime = timedelta(days=30)
                
                flash('Login realizado com sucesso!', 'success')
                return redirect(url_for('index'))
            else:
                flash('Acesso negado. Apenas administradores podem acessar o painel.', 'danger')
        else:
            flash('CPF ou senha inválidos.', 'danger')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user', None)
    flash('Você foi desconectado.', 'info')
    return redirect(url_for('login'))

@app.route('/reset-password', methods=['GET', 'POST'])
@limiter.limit("3 per hour")
def reset_password():
    if request.method == 'POST':
        cpf = request.form.get('cpf')
        user = db.users.find_one({'CPF': cpf})
        
        if user and user.get('user_type') == 0:  # Admin user
            # Generate a temporary token
            token = secrets.token_urlsafe(32)
            expiry = datetime.now() + timedelta(hours=1)
            
            # Store the token in the database
            db.password_resets.insert_one({
                'user_id': user['_id'],
                'token': token,
                'expiry': expiry
            })
            
            # In a real application, you would send an email with the reset link
            # For this demo, we'll just show the token
            flash(f'Token de redefinição de senha: {token}', 'info')
            return redirect(url_for('login'))
        else:
            flash('CPF não encontrado ou não autorizado.', 'danger')
    
    return render_template('reset_password.html')

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
@limiter.limit("3 per hour")
def reset_password_confirm(token):
    # Find the reset token
    reset = db.password_resets.find_one({'token': token})
    
    if not reset or reset['expiry'] < datetime.now():
        flash('Token inválido ou expirado.', 'danger')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if password != confirm_password:
            flash('As senhas não coincidem.', 'danger')
        else:
            # Update the user's password
            db.users.update_one(
                {'_id': reset['user_id']},
                {'$set': {'password': hash_password(password)}}
            )
            
            # Delete the reset token
            db.password_resets.delete_one({'_id': reset['_id']})
            
            flash('Senha redefinida com sucesso!', 'success')
            return redirect(url_for('login'))
    
    return render_template('reset_password_confirm.html')

@app.route('/')
@login_required
def index():
    return render_template('index.html')

@app.route('/api/users', methods=['GET'])
@login_required
def get_users():
    users = list(db.users.find({}, {'_id': 0, 'password': 0}))  # Exclude password field
    return jsonify(users)

@app.route('/api/materials', methods=['GET'])
@login_required
def get_materials():
    materials = list(db.waste_type.find({}, {'_id': 0}))
    return jsonify(materials)

@app.route('/api/stock', methods=['GET'])
@login_required
def get_stock():
    # Get filter parameters
    material_id = request.args.get('material_id')
    
    # Get all measurements
    measurements_query = {}
    if material_id:
        measurements_query['material_id'] = material_id
    measurements = list(db.measurements.find(measurements_query, {'_id': 0}))
    
    # Get all sales
    sales_query = {}
    if material_id:
        sales_query['material_id'] = material_id
    sales = list(db.sales.find(sales_query, {'_id': 0}))
    
    # Calculate current stock for each material
    stock = {}
    material_mapping = get_material_mapping()
    
    # If material_id is provided, only calculate for that material
    if material_id:
        total_measured = sum(m['Weight'] for m in measurements if m['material_id'] == material_id)
        total_sold = sum(s['weight_sold'] for s in sales if s['material_id'] == material_id)
        material_name = material_mapping.get(material_id, f'Material {material_id}')
        stock[material_name] = total_measured - total_sold
    else:
        # Calculate for all materials
        for material in db.waste_type.find({}, {'_id': 0}):
            material_id = material['material_id']
            material_id_str = str(material_id)
            total_measured = sum(m['Weight'] for m in measurements if m['material_id'] == material_id_str)
            total_sold = sum(s['weight_sold'] for s in sales if s['material_id'] == material_id_str)
            material_name = material_mapping.get(material_id, f'Material {material_id}')
            stock[material_name] = total_measured - total_sold
    
    return jsonify(stock)

@app.route('/api/earnings', methods=['GET'])
@login_required
def get_earnings():
    # Get filter parameters
    material_id = request.args.get('material_id')
    
    # Get last month's earnings
    last_month = datetime.now().replace(day=1) - timedelta(days=1)
    sales_query = {
        'date': {'$gte': last_month}
    }
    if material_id:
        sales_query['material_id'] = material_id
    
    sales = list(db.sales.find(sales_query, {'_id': 0}))
    
    total_earnings = sum(sale['price/kg'] * sale['weight_sold'] for sale in sales)
    return jsonify({'total_earnings': total_earnings})

@app.route('/api/earnings-comparison', methods=['GET'])
@login_required
def get_earnings_comparison():
    # Get filter parameters
    material_id = request.args.get('material_id')
    
    # Get earnings for the last 6 months
    six_months_ago = datetime.now() - timedelta(days=180)
    sales_query = {
        'date': {'$gte': six_months_ago}
    }
    if material_id:
        sales_query['material_id'] = material_id
    
    sales = list(db.sales.find(sales_query, {'_id': 0}))
    
    if not sales:
        return jsonify({})
    
    # Group by month and material
    df = pd.DataFrame(sales)
    df['month'] = pd.to_datetime(df['date']).dt.strftime('%Y-%m')
    
    # Get material mapping
    material_mapping = get_material_mapping()
    
    # If material_id is provided, only show data for that material
    if material_id:
        material_name = material_mapping.get(material_id, f'Material {material_id}')
        monthly_earnings = df.groupby('month')['price/kg'].sum().to_dict()
        
        # Convert to the format expected by the frontend
        result = {}
        for month, value in monthly_earnings.items():
            result[f"{month}_{material_name}"] = value
    else:
        monthly_earnings = df.groupby(['month', 'material_id'])['price/kg'].sum().to_dict()
        
        # Convert tuple keys to string keys with material names
        result = {}
        for key, value in monthly_earnings.items():
            material_name = material_mapping.get(key[1], f'Material {key[1]}')
            result[f"{key[0]}_{material_name}"] = value
    
    return jsonify(result)

@app.route('/api/worker-collections')
@login_required
def get_worker_collections():
    # Get current period
    current_date = datetime.now()
    current_month = current_date.month
    current_year = current_date.year
    
    # Get filters
    material_id = request.args.get('material_id')
    worker_id = request.args.get('worker_id')
    
    # Build query for worker contributions
    query = {
        'period': {
            'month': current_month,
            'year': current_year
        }
    }
    
    if material_id:
        query['material_id'] = material_id
    
    if worker_id:
        query['wastepicker_id'] = worker_id
    
    # Get all worker-material combinations for the current period
    worker_contributions = list(db.worker_contributions.find(query))
    print(f"Found {len(worker_contributions)} worker contributions")
    
    # Initialize result dictionary with all worker-material combinations
    result = {}
    
    # Get all workers
    workers_query = {'user_type': {'$in': [1, 2]}}
    if worker_id:
        workers_query['wastepicker_id'] = worker_id
    
    workers = list(db.users.find(workers_query))
    print(f"Found {len(workers)} workers")
    
    # Get all materials
    materials_query = {}
    if material_id:
        materials_query['_id'] = material_id
    
    materials = list(db.materials.find(materials_query))
    print(f"Found {len(materials)} materials")
    
    # Create material name mapping
    material_names = {str(material['_id']): material['name'] for material in materials}
    
    # Initialize result with all worker-material combinations
    for worker in workers:
        worker_id = worker.get('wastepicker_id', worker.get('CPF'))  # Use wastepicker_id if available, fallback to CPF
        result[worker_id] = {
            'name': worker['full_name'],
            'materials': {}
        }
        for material in materials:
            material_id = str(material['_id'])
            result[worker_id]['materials'][material_id] = {
                'name': material['name'],
                'weight': 0,
                'earnings': 0
            }
    
    # Update result with actual contributions
    for contribution in worker_contributions:
        worker_id = contribution.get('wastepicker_id')
        material_id = str(contribution.get('material_id'))
        weight = contribution.get('weight', 0)
        earnings = contribution.get('earnings', 0)
        
        print(f"Processing contribution: worker_id={worker_id}, material_id={material_id}, weight={weight}, earnings={earnings}")
        
        if worker_id in result and material_id in result[worker_id]['materials']:
            result[worker_id]['materials'][material_id]['weight'] = weight
            result[worker_id]['materials'][material_id]['earnings'] = earnings
    
    # Debug logging
    print("Final result structure:")
    for worker_id, worker_data in result.items():
        print(f"Worker: {worker_data['name']}")
        for material_id, material_data in worker_data['materials'].items():
            print(f"  Material {material_id}: weight={material_data['weight']}, earnings={material_data['earnings']}")
    
    return jsonify(result)

@app.route('/api/price-fluctuation', methods=['GET'])
@login_required
def get_price_fluctuation():
    # Get filter parameters
    material_id = request.args.get('material_id')
    print(f"Price Fluctuation - Material ID: {material_id}")
    
    # Build the query
    sales_query = {}
    if material_id:
        sales_query['material_id'] = material_id
    
    print(f"Price Fluctuation - Query: {sales_query}")
    sales = list(db.sales.find(sales_query, {'_id': 0}))
    print(f"Price Fluctuation - Found {len(sales)} sales")
    
    if not sales:
        print("Price Fluctuation - No sales found")
        return jsonify({})
    
    # Group by week and material
    df = pd.DataFrame(sales)
    print(f"Price Fluctuation - Sample data:\n{df.head()}")
    
    # Convert date to datetime if it's not already
    df['date'] = pd.to_datetime(df['date'])
    df['week'] = df['date'].dt.strftime('%Y-%W')
    
    # Sort by date to ensure chronological order
    df = df.sort_values('date')
    
    # Get material mapping
    material_mapping = get_material_mapping()
    
    # If material_id is provided, only show data for that material
    if material_id:
        material_name = material_mapping.get(material_id, f'Material {material_id}')
        # Calculate average price per kg for each week
        weekly_prices = df.groupby('week').apply(
            lambda x: (x['price/kg'] * x['weight_sold']).sum() / x['weight_sold'].sum()
        ).to_dict()
        
        # Convert to the format expected by the frontend
        result = {}
        for week, value in weekly_prices.items():
            result[f"{week}_{material_name}"] = round(value, 2)
    else:
        # Calculate average price per kg for each week and material
        weekly_prices = df.groupby(['week', 'material_id']).apply(
            lambda x: (x['price/kg'] * x['weight_sold']).sum() / x['weight_sold'].sum()
        ).to_dict()
        
        # Convert tuple keys to string keys with material names
        result = {}
        for (week, material_id), value in weekly_prices.items():
            material_name = material_mapping.get(material_id, f'Material {material_id}')
            result[f"{week}_{material_name}"] = round(value, 2)
    
    print(f"Price Fluctuation - Result: {result}")
    return jsonify(result)

@app.route('/api/birthdays', methods=['GET'])
@login_required
def get_birthdays():
    # Get current month
    current_month = datetime.now().month
    users = list(db.users.find({
        '$expr': {
            '$eq': [{'$month': '$Birth date'}, current_month]
        }
    }, {'_id': 0}))
    
    return jsonify(users)

@app.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        # Get current user
        user = db.users.find_one({'CPF': session['user']['cpf']})
        
        if not user:
            flash('Usuário não encontrado.', 'danger')
            return redirect(url_for('logout'))
        
        # Verify current password
        if not verify_password(current_password, user.get('password', '')):
            flash('Senha atual incorreta.', 'danger')
            return render_template('change_password.html')
        
        # Verify new password requirements
        if len(new_password) < 8:
            flash('A nova senha deve ter pelo menos 8 caracteres.', 'danger')
            return render_template('change_password.html')
        
        if not any(c.isupper() for c in new_password):
            flash('A nova senha deve conter pelo menos uma letra maiúscula.', 'danger')
            return render_template('change_password.html')
        
        if not any(c.islower() for c in new_password):
            flash('A nova senha deve conter pelo menos uma letra minúscula.', 'danger')
            return render_template('change_password.html')
        
        if not any(c.isdigit() for c in new_password):
            flash('A nova senha deve conter pelo menos um número.', 'danger')
            return render_template('change_password.html')
        
        if not any(c in '!@#$%^&*(),.?":{}|<>' for c in new_password):
            flash('A nova senha deve conter pelo menos um caractere especial.', 'danger')
            return render_template('change_password.html')
        
        # Verify passwords match
        if new_password != confirm_password:
            flash('As senhas não coincidem.', 'danger')
            return render_template('change_password.html')
        
        # Update password
        db.users.update_one(
            {'_id': user['_id']},
            {'$set': {'password': hash_password(new_password)}}
        )
        
        flash('Senha alterada com sucesso!', 'success')
        return redirect(url_for('index'))
    
    return render_template('change_password.html')

@app.route('/manage-workers', methods=['GET'])
@login_required
def manage_workers():
    # Check if user is admin
    if session['user']['user_type'] != 0:
        flash('Acesso negado. Apenas administradores podem gerenciar trabalhadores.', 'danger')
        return redirect(url_for('index'))
    
    # Get all workers (non-admin users)
    workers = list(db.users.find({'user_type': {'$ne': 0}}))
    
    # Debug logging
    print("\nWorker Data Debug:")
    for worker in workers:
        print(f"Worker: {worker['full_name']}")
        print(f"  user_type: {worker['user_type']} (type: {type(worker['user_type'])})")
        print(f"  CPF: {worker['CPF']}")
        print("---")
    
    return render_template('manage_workers.html', workers=workers)

@app.route('/add-worker', methods=['POST'])
@login_required
def add_worker():
    # Check if user is admin
    if session['user']['user_type'] != 0:
        flash('Acesso negado. Apenas administradores podem adicionar trabalhadores.', 'danger')
        return redirect(url_for('index'))
    
    # Get form data
    full_name = request.form.get('full_name')
    cpf = request.form.get('cpf')
    pis = request.form.get('pis')
    rg = request.form.get('rg')
    birth_date = request.form.get('birth_date')
    gender = request.form.get('gender')
    email = request.form.get('email')
    phone = request.form.get('phone')
    user_type = request.form.get('user_type')
    password = request.form.get('password')
    cooperative_id = request.form.get('cooperative_id')
    
    # Debug logging
    print(f"Form data received: full_name={full_name}, cpf={cpf}, pis={pis}, rg={rg}, birth_date={birth_date}, gender={gender}, email={email}, phone={phone}, user_type={user_type}, password={password}, cooperative_id={cooperative_id}")
    
    # Validate data - check each field individually
    missing_fields = []
    if not full_name: missing_fields.append("Nome Completo")
    if not cpf: missing_fields.append("CPF")
    if not pis: missing_fields.append("PIS")
    if not rg: missing_fields.append("RG")
    if not birth_date: missing_fields.append("Data de Nascimento")
    if not gender: missing_fields.append("Gênero")
    if not email: missing_fields.append("Email")
    if not phone: missing_fields.append("Telefone")
    if user_type is None or user_type == "": missing_fields.append("Tipo de Usuário")
    if not password: missing_fields.append("Senha")
    if not cooperative_id: missing_fields.append("ID da Cooperativa")
    
    if missing_fields:
        flash(f'Todos os campos são obrigatórios. Campos faltantes: {", ".join(missing_fields)}', 'danger')
        return redirect(url_for('manage_workers'))
    
    # Convert user_type to integer
    user_type = int(user_type)
    
    # Check if CPF already exists
    if db.users.find_one({'CPF': cpf}):
        flash('CPF já cadastrado.', 'danger')
        return redirect(url_for('manage_workers'))
    
    # Check if email already exists
    if db.users.find_one({'email': email}):
        flash('Email já cadastrado.', 'danger')
        return redirect(url_for('manage_workers'))
    
    # Check if PIS already exists
    if db.users.find_one({'PIS': pis}):
        flash('PIS já cadastrado.', 'danger')
        return redirect(url_for('manage_workers'))
    
    # Create new worker
    worker = {
        'full_name': full_name,
        'CPF': cpf,
        'PIS': pis,
        'RG': rg,
        'Birth date': datetime.strptime(birth_date, '%Y-%m-%d'),
        'gender': gender,
        'email': email,
        'phone': phone,
        'user_type': user_type,
        'password': hash_password(password),
        'cooperative_id': cooperative_id,
        'created_at': datetime.now(),
        'wastepicker_id': cpf  # Add wastepicker_id field that matches CPF
    }
    
    # Insert into database
    db.users.insert_one(worker)
    
    flash('Trabalhador adicionado com sucesso!', 'success')
    return redirect(url_for('manage_workers'))

@app.route('/update-worker-access', methods=['POST'])
@login_required
def update_worker_access():
    # Check if user is admin
    if session['user']['user_type'] != 0:
        flash('Acesso negado. Apenas administradores podem atualizar acessos.', 'danger')
        return redirect(url_for('index'))
    
    # Get form data
    worker_id = request.form.get('worker_id')
    new_user_type = int(request.form.get('new_user_type'))
    should_reset_password = request.form.get('should_reset_password') == 'on'
    reset_password = request.form.get('reset_password')
    
    # Validate data
    if not worker_id or not new_user_type:
        flash('Todos os campos são obrigatórios.', 'danger')
        return redirect(url_for('manage_workers'))
    
    # Find worker
    worker = db.users.find_one({'_id': ObjectId(worker_id)})
    if not worker:
        flash('Trabalhador não encontrado.', 'danger')
        return redirect(url_for('manage_workers'))
    
    # Update worker
    update_data = {'user_type': new_user_type}
    
    # Reset password if requested
    if should_reset_password and reset_password:
        update_data['password'] = hash_password(reset_password)
    
    # Update in database
    db.users.update_one(
        {'_id': ObjectId(worker_id)},
        {'$set': update_data}
    )
    
    flash('Acesso do trabalhador atualizado com sucesso!', 'success')
    return redirect(url_for('manage_workers'))

@app.route('/delete-worker/<worker_id>', methods=['POST'])
@login_required
def delete_worker(worker_id):
    # Check if user is admin
    if session['user']['user_type'] != 0:
        return jsonify({'success': False, 'message': 'Acesso negado'})
    
    # Find worker
    worker = db.users.find_one({'_id': ObjectId(worker_id)})
    if not worker:
        return jsonify({'success': False, 'message': 'Trabalhador não encontrado'})
    
    # Delete worker
    db.users.delete_one({'_id': ObjectId(worker_id)})
    
    return jsonify({'success': True})

@app.route('/debug/workers', methods=['GET'])
@login_required
def debug_workers():
    # Check if user is admin
    if session['user']['user_type'] != 0:
        flash('Acesso negado. Apenas administradores podem acessar esta página.', 'danger')
        return redirect(url_for('index'))
    
    # Get all workers
    workers = list(db.users.find({}, {'_id': 0, 'password': 0}))
    
    # Print worker data to console
    print("Worker data in database:")
    for worker in workers:
        print(f"Worker: {worker['full_name']}, user_type: {worker['user_type']}, type: {type(worker['user_type'])}")
    
    return render_template('debug_workers.html', workers=workers)

if __name__ == '__main__':
    app.run(debug=True) 