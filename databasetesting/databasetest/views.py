import subprocess
from flask import Blueprint, render_template, request, redirect, url_for, flash, current_app
from flask_login import current_user, login_user, login_required, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os
from werkzeug.utils import secure_filename
import json
from .models import Administrator, Specialist, Patient
from . import db
import cv2
from sqlalchemy.exc import IntegrityError

views = Blueprint('views', __name__)

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@views.route('/')
def role():
    return render_template("role.html")

@views.route('/home')
@login_required
def home():
    specialist = current_user
    return render_template("home.html", specialist=specialist)

@views.route('/index')  # Ensure the user is logged in
@login_required
def index():
    specialist = current_user
    patients = Patient.query.order_by(Patient.date_added.desc()).all()
    return render_template('index.html', specialist=specialist, patients=patients)

@views.route('/indexN')
@login_required
def indexN():
    specialist = current_user
    patients = Patient.query.order_by(Patient.date_added.desc()).all()  # Query to get all patients ordered by the date added
    return render_template('indexN.html', specialist=specialist, patients=patients)

@views.route('/authenticationN', methods=['GET', 'POST'])
def authenticationN():
    role = "Neurologist"

    if request.method == 'POST':
        if 'login' in request.form:
            submitted_userid = request.form.get('user_id')
            password = request.form.get('password')
            specialist = Specialist.query.filter_by(submitted_userid=submitted_userid, role=role).first()
            if specialist and check_password_hash(specialist.password, password):
                login_user(specialist, remember=True)
                return redirect(url_for('views.indexN'))
            else:
                flash('Incorrect user ID or password. Please try again.', category='error')
                return redirect(url_for('views.authenticationN'))

        elif 'signup' in request.form:
            submitted_userid = request.form.get('user_id')
            submitted_email = request.form.get('email')
            first_name = request.form.get('first_name')
            last_name = request.form.get('last_name')
            password = request.form.get('password')

            admin_data = Administrator.query.filter_by(created_userid=submitted_userid, created_email=submitted_email, role=role).first()
            if admin_data:
                hashed_password = generate_password_hash(password)
                new_specialist = Specialist(
                    submitted_userid=submitted_userid,
                    submitted_email=submitted_email,
                    first_name=first_name,
                    last_name=last_name,
                    role=role,
                    password=hashed_password
                )
                db.session.add(new_specialist)
                db.session.commit()
                login_user(new_specialist, remember=True)
                return redirect(url_for('views.indexN'))
            else:
                flash('Unauthorized. Please contact the admin.', category='error')
                return redirect(url_for('views.authenticationN'))

    return render_template('authenticationN.html')

@views.route('/authenticationR', methods=['GET', 'POST'])
def authenticationR():
    role = "Radiologist"

    if request.method == 'POST':
        if 'login' in request.form:
            submitted_userid = request.form.get('user_id')
            password = request.form.get('password')
            specialist = Specialist.query.filter_by(submitted_userid=submitted_userid, role=role).first()
            if specialist and check_password_hash(specialist.password, password):
                login_user(specialist, remember=True)
                return redirect(url_for('views.index'))
            else:
                flash('Incorrect user ID or password. Please try again.', category='error')
                return redirect(url_for('views.authenticationR'))

        elif 'signup' in request.form:
            submitted_userid = request.form.get('user_id')
            submitted_email = request.form.get('email')
            first_name = request.form.get('first_name')
            last_name = request.form.get('last_name')
            password = request.form.get('password')

            admin_data = Administrator.query.filter_by(created_userid=submitted_userid, created_email=submitted_email, role=role).first()
            if admin_data:
                hashed_password = generate_password_hash(password)
                new_specialist = Specialist(
                    submitted_userid=submitted_userid,
                    submitted_email=submitted_email,
                    first_name=first_name,
                    last_name=last_name,
                    role=role,
                    password=hashed_password
                )
                db.session.add(new_specialist)
                db.session.commit()
                login_user(new_specialist, remember=True)
                return redirect(url_for('views.index'))
            else:
                flash('Unauthorized. Please contact the admin.', category='error')
                return redirect(url_for('views.authenticationR'))

    return render_template('authenticationR.html')

@views.route('/base', methods=['GET', 'POST'])
def base():
    if request.method == 'POST':
        created_email = request.form.get('email')
        created_userid = request.form.get('userid')
        role = request.form.get('user_role')

        new_admin = Administrator(created_userid=created_userid, created_email=created_email, role=role)
        db.session.add(new_admin)
        db.session.commit()

        return render_template('base.html')

    return render_template("base.html")

def generate_unique_custom_id():
    patient_count = Patient.query.count()
    while True:
        next_custom_id = f'P-{patient_count + 1:02d}'
        if not Patient.query.filter_by(custom_id=next_custom_id).first():
            return next_custom_id
        patient_count += 1

@views.route('/homepage', methods=['GET', 'POST'])
@login_required
def homepage():
    if request.method == 'POST':
        specialist_id = current_user.id
        specialist = Specialist.query.get_or_404(specialist_id)

        print(f"Form Data: {request.form}")

        mri_image = request.files['mri_image']
        mri_filename = None

        upload_folder = current_app.config['UPLOAD_FOLDER']
        os.makedirs(upload_folder, exist_ok=True)

        if mri_image and allowed_file(mri_image.filename):
            mri_filename = secure_filename(mri_image.filename)
            mri_file_path = os.path.join(upload_folder, mri_filename)
            mri_image.save(mri_file_path)

        try:
            new_patient = Patient(
                first_name=request.form['first_name'],
                last_name=request.form['last_name'],
                age=request.form['age'],
                gender=request.form['gender'],
                condition=request.form['condition'],
                patient_ic=request.form.get('patient_ic'),
                contact_number=request.form.get('contact_number'),
                specialist_id=specialist_id,
                specialist_first_name=specialist.first_name,
                specialist_last_name=specialist.last_name,
                custom_id=generate_unique_custom_id(),
                date_added=datetime.utcnow(),
                mri_image=mri_filename
            )

            db.session.add(new_patient)
            db.session.commit()
            return redirect(url_for('views.homepage'))
        except IntegrityError:
            db.session.rollback()
            flash('There was an error adding the patient. Please try again.', 'danger')
            return redirect(url_for('views.homepage'))
    else:
        specialists = Specialist.query.all()
        specialist = current_user
        return render_template('homepage.html', specialists=specialists, specialist=specialist)

@views.route('/patients')
@login_required
def patients():
    patients = Patient.query.order_by(Patient.custom_id).all()
    specialist = current_user
    return render_template('patients.html', patients=patients, specialist=specialist)

@views.route('/patientsN')
@login_required
def patientsN():
    patients = Patient.query.order_by(Patient.custom_id).all()
    specialist = current_user
    return render_template('patientsN.html', patients=patients, specialist=specialist)

@views.route('/patient/<int:patient_id>')
@login_required
def patient(patient_id):
    patient = Patient.query.get_or_404(patient_id)
    specialist = Specialist.query.get(patient.specialist_id) if patient.specialist_id else current_user
    return render_template('patient.html', patient=patient, specialist=specialist)

@views.route('/patientNN/<int:patient_id>')
@login_required
def patientNN(patient_id):
    patient = Patient.query.get_or_404(patient_id)
    specialist = current_user
    return render_template('patientNN.html', patient=patient, specialist=specialist)

@views.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('views.role'))

@views.route('/bas')
def bas():
    specialists = Specialist.query.order_by(Specialist.date_added.desc()).all()
    return render_template('bas.html', specialists=specialists)

@views.route('/admins')
def admins():
    specialists = Specialist.query.order_by(Specialist.id).all()
    specialist = current_user
    return render_template('admins.html', specialists=specialists, specialist=specialist)

@views.route('/specialist/<int:specialist_id>', methods=['GET'])
def specialist(specialist_id):
    specialist = Specialist.query.get_or_404(specialist_id)
    return render_template('specialist.html', specialist=specialist)

@views.route('/admin/<int:specialist_id>', methods=['GET'])
def admin(specialist_id):
    specialist = Specialist.query.get_or_404(specialist_id)
    return render_template('admin.html', specialist=specialist)

@views.route('/braintumor', methods=['GET', 'POST'])
@login_required
def braintumor():
    specialist = current_user
    mri_image = request.args.get('mri_image', None)
    patient_id = request.args.get('patient_id', None)

    if request.method == 'POST':
        mri_image = request.form.get('mri_image')
        patient_id = request.form.get('patient_id')
        if not mri_image or not patient_id:
            return "No MRI image or patient ID provided", 400
        return redirect(url_for('views.process_mri', mri_image=mri_image, patient_id=patient_id))

    return render_template('braintumor.html', specialist=specialist, mri_image=mri_image, patient_id=patient_id)

@views.route('/select_mri', methods=['GET', 'POST'])
@login_required
def select_mri():
    patients = Patient.query.all()
    specialist = current_user

    if request.method == 'POST':
        patient_id = request.form.get('patient_id')
        return redirect(url_for('views.mri_images', patient_id=patient_id))

    return render_template('select_mri.html', patients=patients, specialist=specialist)

@views.route('/mri_images/<int:patient_id>', methods=['GET', 'POST'])
@login_required
def mri_images(patient_id):
    patient = Patient.query.get_or_404(patient_id)
    specialist = current_user

    if request.method == 'POST':
        mri_image = request.form['mri_image']
        return redirect(url_for('views.braintumor', mri_image=mri_image, patient_id=patient_id))

    return render_template('mri_images.html', patient=patient, specialist=specialist)

@views.route('/delete_patient/<int:patient_id>', methods=['POST'])
@login_required
def delete_patient(patient_id):
    patient = Patient.query.get_or_404(patient_id)
    db.session.delete(patient)
    db.session.commit()
    flash('Patient deleted successfully!', 'success')
    return redirect(url_for('views.index'))

@views.route('/delete_specialist/<int:specialist_id>', methods=['POST'])
def delete_specialist(specialist_id):
    specialist = Specialist.query.get_or_404(specialist_id)
    db.session.delete(specialist)
    db.session.commit()
    return redirect(url_for('views.bas'))

@views.route('/process_mri', methods=['POST'])
@login_required
def process_mri():
    specialist = current_user
    mri_image = request.form.get('mri_image')
    patient_id = request.form.get('patient_id')

    if not mri_image or not patient_id:
        return "No MRI image or patient ID provided", 400

    mri_image_path = os.path.join(current_app.config['UPLOAD_FOLDER'], mri_image)

    python_executable_path_3_11 = r"C:\Users\mfeng\OneDrive\Desktop\HELP_MF\.venv\Scripts\python.exe"
    test5_script_path = r"C:\Users\mfeng\OneDrive\Desktop\HELP_MF\test5.py"
    model_path = r"C:\Users\mfeng\OneDrive\Desktop\HELP_MF\efficientnet_model_1.h5"

    python_executable_path_3_8 = r"C:\Users\mfeng\OneDrive\Desktop\visual_env\venv\Scripts\python.exe"
    visual_env_script_path = r"C:\Users\mfeng\OneDrive\Desktop\visual_env\visual_script.py"
    api_url = "https://detect.roboflow.com"
    api_key = "BHKI2g8uI3d93Tw9S2Ic"
    model_id = "brain-tumor-scans/2"

    try:
        result_test5 = subprocess.run(
            [python_executable_path_3_11, test5_script_path, '--model_path', model_path, '--image_path', mri_image_path],
            capture_output=True,
            text=True,
            check=True
        )
        prediction_output = result_test5.stdout.strip()
        tumor_type = prediction_output.split()[-2]
        tumor_type = f"{tumor_type} Tumor"

        result_visual_env = subprocess.run(
            [python_executable_path_3_8, visual_env_script_path, '--api_url', api_url, '--api_key', api_key, '--image_path', mri_image_path, '--model_id', model_id],
            capture_output=True,
            text=True,
            check=True
        )
        visual_output = result_visual_env.stdout.strip()
        corrected_output = visual_output.replace("'", "\"")

        try:
            visual_output_json = json.loads(corrected_output)
        except json.JSONDecodeError as e:
            error_message = f"JSON decode error: {e}\nCorrected output: {corrected_output}"
            print(error_message)
            return error_message, 500

        annotated_image_path = os.path.join(current_app.config['UPLOAD_FOLDER'], f"annotated_{mri_image}")
        image = cv2.imread(mri_image_path)

        report = ["The MRI image has detected a brain tumor."]
        for prediction in visual_output_json['predictions']:
            x, y, width, height = int(prediction['x']), int(prediction['y']), int(prediction['width']), int(prediction['height'])
            top_left = (x - width // 2, y - height // 2)
            bottom_right = (x + width // 2, y + height // 2)
            cv2.rectangle(image, top_left, bottom_right, (0, 255, 0), 2)
            label = f"{prediction['class']} ({prediction['confidence']:.2f})"
            cv2.putText(image, label, (top_left[0], top_left[1] - 10), cv2.FONT_HERSHEY_SIMPLEX, 0.5, (0, 255, 0), 2)
            report.append(f"The brain tumor detected is {tumor_type}, and it is located at {x}, {y}, {width}, {height}.")

        cv2.imwrite(annotated_image_path, image)

        patient = Patient.query.get_or_404(patient_id)
        patient.scanned_image_path = f"uploads/annotated_{mri_image}"
        patient.detection_report = '\n'.join(report)
        db.session.commit()

    except subprocess.CalledProcessError as e:
        error_message = f"Error in MRI prediction: {e.stderr}"
        print(error_message)
        return f"Error in MRI prediction: {e.stderr}", 500
    except FileNotFoundError as e:
        error_message = f"FileNotFoundError: {e}"
        print(error_message)
        return f"FileNotFoundError: {e}", 500
    except Exception as e:
        error_message = f"An unexpected error occurred: {e}"
        print(error_message)
        return f"An unexpected error occurred: {e}", 500

    return render_template('process.html', specialist=specialist, annotated_image=f"uploads/annotated_{mri_image}", report=report, patient=patient)

@views.route('/save_report', methods=['POST'])
@login_required
def save_report():
    patient_id = request.form.get('patient_id')
    scanned_image_path = request.form.get('scanned_image_path')
    detection_report = request.form.get('detection_report')

    if not patient_id or not scanned_image_path or not detection_report:
        return "Missing required data", 400

    patient = Patient.query.get_or_404(patient_id)
    patient.scanned_image_path = scanned_image_path
    patient.detection_report = detection_report

    db.session.commit()

    return redirect(url_for('views.index'))