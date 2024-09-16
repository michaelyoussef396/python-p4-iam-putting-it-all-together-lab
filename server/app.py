#!/usr/bin/env python3

from flask import request, session
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError
from config import app, db, api
from models import User, Recipe

class Signup(Resource):
    def post(self):
        data = request.get_json()

        # Check if the required fields are present
        if 'username' not in data or not data['username']:
            return {'error': 'Username is required'}, 422
        if 'password' not in data or not data['password']:
            return {'error': 'Password is required'}, 422
        
        try:
            new_user = User(
                username=data['username'],
                bio=data.get('bio', ''),
                image_url=data.get('image_url', '')
            )
            new_user.set_password(data['password'])  # Set and hash the password
            db.session.add(new_user)
            db.session.commit()
            session['user_id'] = new_user.id  # Log in the user by saving their ID in the session
            return {
                'id': new_user.id,
                'username': new_user.username,
                'bio': new_user.bio,
                'image_url': new_user.image_url
            }, 201
        except IntegrityError:
            db.session.rollback()
            return {'error': 'Username already exists'}, 422

class CheckSession(Resource):
    def get(self):
        user_id = session.get('user_id')
        if not user_id:
            return {'error': 'Unauthorized'}, 401
        user = User.query.get(user_id)
        return {
            'id': user.id,
            'username': user.username,
            'bio': user.bio,
            'image_url': user.image_url
        }, 200


class Login(Resource):
    def post(self):
        data = request.get_json()
        user = User.query.filter_by(username=data['username']).first()

        if user and user.authenticate(data['password']):
            session['user_id'] = user.id  # Ensure user ID is stored in the session
            return user.to_dict(), 200
        
        return {'error': 'Invalid credentials'}, 401


class Logout(Resource):
    def delete(self):
        if 'user_id' not in session or session['user_id'] is None:
            return {'error': 'Unauthorized, no active session'}, 401

        session.pop('user_id', None)
        return {}, 204


class RecipeIndex(Resource):
    def get(self):
        user_id = session.get('user_id')
        if not user_id:
            return {'error': 'Unauthorized'}, 401
        
        user = User.query.get(user_id)
        if not user:
            return {'error': 'User not found'}, 404
        
        recipes = [recipe.to_dict() for recipe in user.recipes]
        return recipes, 200

    def post(self):
        user_id = session.get('user_id')
        if not user_id:
            return {'error': 'Unauthorized'}, 401
        data = request.get_json()
        if len(data['instructions']) < 50:
            return {'error': 'Instructions must be at least 50 characters'}, 422
        new_recipe = Recipe(
            title=data['title'],
            instructions=data['instructions'],
            minutes_to_complete=data['minutes_to_complete'],
            user_id=user_id
        )
        db.session.add(new_recipe)
        db.session.commit()
        return {
            'title': new_recipe.title,
            'instructions': new_recipe.instructions,
            'minutes_to_complete': new_recipe.minutes_to_complete
        }, 201


# Adding resources to Flask-Restful API
api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')


if __name__ == '__main__':
    app.run(port=5555, debug=True)
