from pymongo import MongoClient
from datetime import datetime, timedelta
import random
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# MongoDB connection
client = MongoClient(os.getenv('MONGODB_URI', 'mongodb://localhost:27017/'))
db = client['DMS-LocalTest']

# Clear existing data
db.users.delete_many({})
db.measurements.delete_many({})
db.sales.delete_many({})

# Insert users
users = [
    {
        "CPF": "12345678901",
        "full_name": "João Silva",
        "coopeative_id": "1",
        "wastepicker_id": "WP001",
        "user_type": 1,
        "Birth date": datetime(1985, 5, 15),
        "Entry date": datetime(2020, 1, 10),
        "PIS": "123456789",
        "RG": "12345678",
        "gender": "M"
    },
    {
        "CPF": "23456789012",
        "full_name": "Maria Oliveira",
        "coopeative_id": "1",
        "wastepicker_id": "WP002",
        "user_type": 1,
        "Birth date": datetime(1990, 8, 22),
        "Entry date": datetime(2021, 3, 5),
        "PIS": "234567890",
        "RG": "23456789",
        "gender": "F"
    },
    {
        "CPF": "34567890123",
        "full_name": "Pedro Santos",
        "coopeative_id": "1",
        "wastepicker_id": "WP003",
        "user_type": 1,
        "Birth date": datetime(1988, 4, 10),
        "Entry date": datetime(2019, 11, 20),
        "PIS": "345678901",
        "RG": "34567890",
        "gender": "M"
    },
    {
        "CPF": "45678901234",
        "full_name": "Ana Costa",
        "coopeative_id": "1",
        "wastepicker_id": "WP004",
        "user_type": 1,
        "Birth date": datetime(1992, 12, 3),
        "Entry date": datetime(2022, 2, 15),
        "PIS": "456789012",
        "RG": "45678901",
        "gender": "F"
    },
    {
        "CPF": "56789012345",
        "full_name": "Carlos Ferreira",
        "coopeative_id": "1",
        "wastepicker_id": "WP005",
        "user_type": 0,  # Admin
        "Birth date": datetime(1975, 7, 18),
        "Entry date": datetime(2018, 6, 1),
        "PIS": "567890123",
        "RG": "56789012",
        "gender": "M"
    }
]
db.users.insert_many(users)
print("Users inserted")

# Generate measurements data
measurements = []
wastepickers = ["WP001", "WP002", "WP003", "WP004"]
materials_ids = [str(i) for i in range(1, 43)]  # Materials from 1 to 42
device_id = "1"  # Only cooperative with id 1 exists

# Generate data for the last 90 days
end_date = datetime.now()
start_date = end_date - timedelta(days=90)

current_date = start_date
while current_date <= end_date:
    # Generate 2-5 measurements per day
    for _ in range(random.randint(2, 5)):
        wastepicker_id = random.choice(wastepickers)
        material_id = random.choice(materials_ids)
        
        # Determine if the bag was filled that day
        bag_filled = random.choice(["Y", "N"])
        
        # Generate a random weight between 1 and 50 kg
        weight = round(random.uniform(1, 50), 2)
        
        # Create timestamp with random hour and minute
        timestamp = current_date.replace(
            hour=random.randint(8, 17),
            minute=random.randint(0, 59)
        )
        
        measurements.append({
            "Weight": weight,
            "timestamp": timestamp,
            "wastepicker_id": wastepicker_id,
            "material_id": material_id,
            "device_id": device_id,
            "bag_filled": bag_filled
        })
    
    current_date += timedelta(days=1)

db.measurements.insert_many(measurements)
print("Measurements inserted")

# Generate sales data
sales = []
# Generate data for the last 180 days (6 months)
end_date = datetime.now()
start_date = end_date - timedelta(days=180)

current_date = start_date
while current_date <= end_date:
    # Generate 1-3 sales per day
    for _ in range(random.randint(1, 3)):
        material_id = random.choice(materials_ids)
        cooperative_id = "1"  # Only cooperative with id 1 exists
        
        # Generate a random price between 0.5 and 5.0 per kg
        price_per_kg = round(random.uniform(0.5, 5.0), 2)
        
        # Generate a random weight between 10 and 200 kg
        weight_sold = round(random.uniform(10, 200), 2)
        
        # Create date with random hour and minute
        date = current_date.replace(
            hour=random.randint(9, 16),
            minute=random.randint(0, 59)
        )
        
        sales.append({
            "material_id": material_id,
            "cooperative_id": cooperative_id,
            "price/kg": price_per_kg,
            "weight_sold": weight_sold,
            "date": date
        })
    
    current_date += timedelta(days=1)

db.sales.insert_many(sales)
print("Sales inserted")

print("Database populated successfully!") 