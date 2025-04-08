from flask import Flask, request, jsonify, send_file
from flask_bcrypt import Bcrypt
import os
import json
import logging
from datetime import datetime

app = Flask(__name__)
bcrypt = Bcrypt(app)

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# In-memory storage for API settings
api_settings = []

@app.route('/')
def index():
    return send_file('test_api_form.html')

@app.route('/api/settings', methods=['POST'])
def save_api_settings():
    try:
        data = request.json
        provider = data.get('provider')
        api_key = data.get('api_key')
        model_name = data.get('model_name')
        is_active = data.get('is_active', False)
        temperature = data.get('temperature', 0.7)
        max_tokens = data.get('max_tokens', 1000)
        
        # Log received data (without the actual API key for security)
        logger.info(f"Received API settings: provider={provider}, model={model_name}, is_active={is_active}")
        
        # Validate required fields
        if not all([provider, api_key, model_name]):
            missing_fields = []
            if not provider:
                missing_fields.append('provider')
            if not api_key:
                missing_fields.append('api_key')
            if not model_name:
                missing_fields.append('model_name')
                
            error_msg = f'Missing required fields: {", ".join(missing_fields)}'
            logger.error(error_msg)
            return jsonify({
                'status': 'error',
                'message': error_msg
            }), 400
        
        # Validate provider value
        valid_providers = ['openai', 'anthropic', 'gemini', 'huggingface', 'grok']
        if provider not in valid_providers:
            error_msg = f'Invalid provider. Must be one of: {", ".join(valid_providers)}'
            logger.error(error_msg)
            return jsonify({
                'status': 'error',
                'message': error_msg
            }), 400
        
        try:
            # Hash the API key before storing
            hashed_key = bcrypt.generate_password_hash(api_key).decode('utf-8')
            logger.info(f"API key hashed successfully")
        except Exception as hash_error:
            error_msg = f"Error hashing API key: {str(hash_error)}"
            logger.error(error_msg)
            return jsonify({
                'status': 'error',
                'message': error_msg
            }), 500
        
        try:
            # Check if settings already exist for this provider
            existing_index = None
            for i, setting in enumerate(api_settings):
                if setting['api_provider'] == provider:
                    existing_index = i
                    break
            
            if existing_index is not None:
                # Update existing settings
                api_settings[existing_index]['api_key'] = hashed_key
                api_settings[existing_index]['model_name'] = model_name
                api_settings[existing_index]['is_active'] = is_active
                api_settings[existing_index]['temperature'] = temperature
                api_settings[existing_index]['max_tokens'] = max_tokens
                api_settings[existing_index]['updated_at'] = datetime.utcnow().isoformat()
                logger.info(f"Updated existing {provider} API settings")
            else:
                # Create new settings
                new_setting = {
                    'api_provider': provider,
                    'api_key': hashed_key,
                    'model_name': model_name,
                    'is_active': is_active,
                    'temperature': temperature,
                    'max_tokens': max_tokens,
                    'created_at': datetime.utcnow().isoformat(),
                    'updated_at': datetime.utcnow().isoformat()
                }
                api_settings.append(new_setting)
                logger.info(f"Added new {provider} API settings")
        except Exception as db_error:
            error_msg = f"Database error: {str(db_error)}"
            logger.error(error_msg)
            return jsonify({
                'status': 'error',
                'message': error_msg
            }), 500
        
        try:
            # If this provider is being set as active, deactivate others
            if is_active:
                for setting in api_settings:
                    if setting['api_provider'] != provider:
                        setting['is_active'] = False
                logger.info(f"Deactivated other API providers")
        except Exception as update_error:
            error_msg = f"Error updating active status: {str(update_error)}"
            logger.error(error_msg)
            return jsonify({
                'status': 'error',
                'message': error_msg
            }), 500
        
        logger.info(f"Successfully saved API settings for {provider}")
        return jsonify({
            'status': 'success',
            'message': 'API settings saved successfully'
        })
        
    except Exception as e:
        error_msg = f"Error saving API settings: {str(e)}"
        logger.error(error_msg)
        return jsonify({
            'status': 'error',
            'message': f'An error occurred: {str(e)}'
        }), 500

@app.route('/api/settings', methods=['GET'])
def get_api_settings():
    try:
        # Format settings for the frontend, masking sensitive data
        formatted_settings = []
        for setting in api_settings:
            formatted_settings.append({
                'api_provider': setting['api_provider'],
                'model_name': setting['model_name'],
                'is_active': setting['is_active'],
                'temperature': setting['temperature'],
                'max_tokens': setting['max_tokens'],
                'updated_at': setting['updated_at'],
                'has_key': True  # Indicate a key exists without exposing it
            })
        
        return jsonify({
            'status': 'success',
            'settings': formatted_settings
        })
    except Exception as e:
        logger.error(f"Error retrieving API settings: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': f'Failed to retrieve API settings: {str(e)}'
        }), 500

@app.route('/api/settings/test', methods=['POST'])
def test_api_settings():
    try:
        data = request.json
        provider = data.get('provider')
        api_key = data.get('api_key')
        model_name = data.get('model_name')
        
        # Validate required fields
        if not all([provider, api_key, model_name]):
            return jsonify({
                'status': 'error',
                'message': 'Missing required fields: provider, api_key, and model_name are required'
            }), 400
        
        # Validate provider value
        valid_providers = ['openai', 'anthropic', 'gemini', 'huggingface', 'grok']
        if provider not in valid_providers:
            return jsonify({
                'status': 'error',
                'message': f'Invalid provider. Must be one of: {", ".join(valid_providers)}'
            }), 400
        
        # For testing purposes, just simulate a successful connection
        logger.info(f"Successfully tested {provider} API connection (simulated)")
        
        return jsonify({
            'status': 'success',
            'message': 'API connection successful (simulated)'
        })
        
    except Exception as e:
        error_msg = f"API test encountered an unexpected error: {str(e)}"
        logger.error(error_msg)
        return jsonify({
            'status': 'error',
            'message': f'An unexpected error occurred: {str(e)}'
        }), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True) 