from . import db
from flask_login import UserMixin
from datetime import datetime

class Administrator(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    created_userid = db.Column(db.String(50), unique=True, nullable=False)
    created_email = db.Column(db.String(150), unique=True, nullable=False)
    role = db.Column(db.String(50), nullable=False)  # Make sure this line is exactly as shown

class Specialist(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    submitted_userid = db.Column(db.String(50), nullable=False)
    submitted_email = db.Column(db.String(150), nullable=False)
    first_name = db.Column(db.String(100))
    role = db.Column(db.String(50))  # This is the correct column name
    last_name = db.Column(db.String(100))
    password = db.Column(db.String(200))
    date_added = db.Column(db.DateTime, default=datetime.utcnow)

class Patient(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    first_name = db.Column(db.String(100), nullable=False)
    last_name = db.Column(db.String(100), nullable=False)
    age = db.Column(db.Integer, nullable=False)
    gender = db.Column(db.String(10), nullable=False)
    condition = db.Column(db.String(100), nullable=False)
    specialist_id = db.Column(db.Integer, db.ForeignKey('specialist.id', ondelete='SET NULL'))
    specialist_first_name = db.Column(db.String(100))  # Field for specialist's first name
    specialist_last_name = db.Column(db.String(100))   # Field for specialist's last name
    patient_ic = db.Column(db.String(100), nullable=False)
    custom_id = db.Column(db.String(10), unique=True, nullable=False)
    contact_number = db.Column(db.String(15), nullable=False)
    date_added = db.Column(db.DateTime, default=datetime.utcnow)
    mri_image = db.Column(db.String(200))  # Field for MRI image
    scanned_image_path = db.Column(db.String(200))  # New field for scanned image path
    detection_report = db.Column(db.Text)  # New field for detection report
