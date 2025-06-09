# DMS Dashboard - First deploy with python and HTML, new version mad with JS available at: https://github.com/ErasmusEgalitarian/DMS-MGM-JS_APP

A web application to display and manage data from the MongoDB database for waste collection cooperatives.

## Features

- Real-time stock monitoring
- Monthly earnings tracking
- Worker collection statistics
- Price fluctuation analysis
- Birthday notifications
- Interactive graphs and charts

## Prerequisites

- Python 3.8 or higher
- MongoDB (local installation or MongoDB Atlas)
- pip (Python package manager)

## Installation

1. Clone this repository:
```bash
git clone <repository-url>
cd dms-dashboard
```

2. Create a virtual environment (recommended):
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install the required packages:
```bash
pip install -r requirements.txt
```

4. Create a `.env` file in the root directory with your MongoDB connection string:
```
MONGODB_URI=mongodb://localhost:27017/
```

## Running the Application

1. Make sure MongoDB is running on your system

2. Start the Flask application:
```bash
python app.py
```

3. Open your web browser and navigate to:
```
http://localhost:5000
```

## Project Structure

- `app.py`: Main Flask application with API endpoints
- `templates/index.html`: Frontend dashboard interface
- `requirements.txt`: Python package dependencies

## API Endpoints

- `/api/users`: Get all users
- `/api/materials`: Get all materials
- `/api/stock`: Get current stock levels
- `/api/earnings`: Get last month's earnings
- `/api/earnings-comparison`: Get earnings comparison for the last 6 months
- `/api/worker-collections`: Get worker collection statistics
- `/api/price-fluctuation`: Get price fluctuation data for the last 6 weeks
- `/api/birthdays`: Get birthdays for the current month

## Contributing

Feel free to submit issues and enhancement requests! 
