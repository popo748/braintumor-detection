from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_migrate import Migrate
import os

db = SQLAlchemy()
login_manager = LoginManager()

def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'dskds oewmlmfmsdlnfljds'
    app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+mysqlconnector://root:Chiamingfeng0722!!@localhost/Braindy'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    # app.config['UPLOAD_FOLDER'] = os.path.join(os.getcwd(), 'uploads')  # Define the upload folder
    app.config['UPLOAD_FOLDER'] = os.path.join(app.root_path, 'static/uploads')  # Corrected line
    app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # Max file size: 16MB
    
    db.init_app(app)
    login_manager.init_app(app)

    # Import your models here to ensure they are registered with SQLAlchemy
    from .models import Administrator, Specialist, Patient

    # Initialize Flask-Migrate and link it to the app and database
    migrate = Migrate(app, db)

    # Register blueprints
    from .views import views
    from .auth import auth
    app.register_blueprint(views, url_prefix='/')
    app.register_blueprint(auth, url_prefix='/')

    @login_manager.user_loader
    def load_user(user_id):
        return Specialist.query.get(int(user_id))

    return app