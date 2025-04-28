# MongoDB and DMS Dashboard Demo

A simple demo on how to display data collected on the mongoDB database

## Features

- List users working at the cooperative
- Order list table with user information
- Responsive design
- Real-time data updates
- How much of each material they have in stock (take all the measurment for each material and subtract what has been sold)
- How much they earned in the last month
- How much money they earned in comparisson with previous months for each material and in total in a single interactive graph (bar graph showing how much they earned for each month side by side)
- Capacity to add new workers
- Capacity to exclude workers
- Capacity to add sales information
- Graph that shows how much each worker has collected for each material and user (one live graph with capacity to change the information being displayed), accomodate the function to see if the bag was filled by only one worker or more, it can be done by checking if it was filed on the day before or not, if it was not filled on the day before, it means you need to subtract the total new weight from previous measurments of the bag being not completed with that material beacuse each day one person is responsible for the bag and should be payed based on the quantity they collected and a bag gan take a few days to be filled depending on the material
- A graph showing how much the price for each material has fluctuaded in the last 6 weeks
- Birthdays of the month

## Prerequisites so far

- MongoDB (local installation or MongoDB Atlas)

## Data Structure

The application uses 5 main collections:

1. Measurments collection:
   - Weight
   - timestamp (when the material was weighted)
   - Wastepicker_id (references users collection)
   - Material_id (references materials collection)
   - Device_id (references cooperatives collection)
   - Bag_filled (Y(Bag filled by more than one worker and completed by the last one) by N(bag not filled that day, will continued to be filled on the following day))

2. Users Collection:
   - CPF
   - full name
   - Cooperative_id (witch cooperative the user works for)
   - Wastepicker_id (unique ID for the wastepicker on the cooperative)
   - User_type (0 = admin and 1 = normal user)
   - Birth date
   - Entry date (day they joined the cooperative)
   - PIS 
   - RG 
   - Gender

3. Materials Collection:
   - Material
   - Material id

4. Cooperatives collection:
   - Cooperative name
   - Device_id (witch device is sending the weight data)
   - Cooperative_id

5. Sales collection:
   - Material_id
   - Cooperative_id
   - Price/kg
   - Weight_sold 

## Technologies Used so far

- Database: MongoDB
