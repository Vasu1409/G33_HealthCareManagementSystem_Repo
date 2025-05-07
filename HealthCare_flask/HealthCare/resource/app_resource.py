from flask_restful import Resource
from flask import request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import create_access_token
from flask_jwt_extended import jwt_required, get_jwt_identity

from models import User
from extensions import db
import re

class RegisterAPI(Resource):
    def post(self):
        data = request.get_json()
        if not data:
            return {"message": "No input data provided"}, 400

        full_name = data.get("full_name")
        email = data.get("email")
        password = data.get("password")
        dob = data.get("dob")
        gender = data.get("gender")

        if not all([full_name, email, password, dob, gender]):
            return {"message": "Missing required fields"}, 400
        
        if User.query.filter_by(email=email).first():
            return {"message": "Email already registered."}, 400

        if not re.match(r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$', email):
            return {"message": "Invalid email format"}, 400

        if len(password) < 8 or not any(char.isdigit() for char in password) or not any(char.isalpha() for char in password):
            return {"message": "Weak password"}, 400

        hashed_password = generate_password_hash(password, method="pbkdf2:sha256")
        new_user = User(full_name=full_name, email=email, password=hashed_password, dob=dob, gender=gender)

        try:
            db.session.add(new_user)
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            return {"message": f"Error: {str(e)}"}, 500

        return {"message": "Signup successful."}, 201


class LoginAPI(Resource):
    def post(self):
        """User login API"""
        try:
            data = request.get_json()
            if not data:
                return {"message": "No input data provided"}, 400
                
            # Get email and password
            email = data.get("email")
            password = data.get("password")
            
            if not email or not password:
                return {"message": "Email and password are required"}, 400
                
            # Find user by email
            user = User.query.filter_by(email=email).first()
            
            # Check if user exists and password is correct
            if not user or not check_password_hash(user.password, password):
                return {"message": "Invalid email or password"}, 401
                
            # Create access token with string identity
            access_token = create_access_token(identity=str(user.id))
            
            return {
                "message": "Login successful",
                "access_token": access_token,
                "user_id": user.id
            }, 200
            
        except Exception as e:
            return {"message": f"Error: {str(e)}"}, 500
 
 
class UserListAPI(Resource):
    @jwt_required()
    def get(self):
        """Get all users from the database"""
        try:
            # Get current user from JWT identity (this will be a string now)
            current_user_id = get_jwt_identity()
            
            # Query all users from the database
            users = User.query.all()
            
            # Convert users to dictionary format for JSON response
            user_list = []
            for user in users:
                user_data = {
                    "id": user.id,
                    "full_name": user.full_name,
                    "email": user.email,
                    "dob": user.dob,
                    "gender": user.gender
                }
                user_list.append(user_data)
                
            return user_list, 200
        except Exception as e:
            return {"message": f"Error: {str(e)}"}, 500

# Optional: Class to get a specific user by ID
class UserDetailAPI(Resource):
    @jwt_required()
    def get(self, user_id):
        """Get a specific user by ID"""
        try:
            # Get current user from JWT identity (this will be a string now)
            current_user_id = get_jwt_identity()
            
            # Query the specific user
            user = User.query.get(int(user_id))
            
            if not user:
                return {"message": "User not found"}, 404
                
            # Convert user to dictionary format for JSON response
            user_data = {
                "id": user.id,
                "full_name": user.full_name,
                "email": user.email,
                "dob": user.dob,
                "gender": user.gender
            }
                
            return user_data, 200
        except Exception as e:
            return {"message": f"Error: {str(e)}"}, 500