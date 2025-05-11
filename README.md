# sales_tracker

Imports orders from ShipStation
- On June 1, 2025, Shipstation is introducing new API requirements (requiring a higher tier plan) and this project will not be updated which means it will stop functioning with Shipstation.

Allows calculation of totals for WA state taxes

Allows creation of invoices/sales receipts, customers, and products.

- Create Python venv
- Activate venv
- Install requirements
- Create admin user
-- flask create-admin
-- Enter username and password
- Set Secret Key
-- export FLASK_SECRET_KEY='your-very-long-and-random-string-here'
- Run app.py
- Enter ShipStation api info if used
