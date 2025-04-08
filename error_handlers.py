from flask import jsonify, render_template, request
from werkzeug.exceptions import HTTPException
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class APIError(Exception):
    """Base class for API errors"""
    def __init__(self, message, status_code=500, payload=None):
        super().__init__()
        self.message = message
        self.status_code = status_code
        self.payload = payload

    def to_dict(self):
        rv = dict(self.payload or ())
        rv['message'] = self.message
        rv['status'] = 'error'
        return rv

class ValidationError(APIError):
    """Raised when input validation fails"""
    def __init__(self, message, payload=None):
        super().__init__(message, status_code=400, payload=payload)

class AuthenticationError(APIError):
    """Raised when authentication fails"""
    def __init__(self, message, payload=None):
        super().__init__(message, status_code=401, payload=payload)

class AuthorizationError(APIError):
    """Raised when user is not authorized"""
    def __init__(self, message, payload=None):
        super().__init__(message, status_code=403, payload=payload)

class ResourceNotFoundError(APIError):
    """Raised when a requested resource is not found"""
    def __init__(self, message, payload=None):
        super().__init__(message, status_code=404, payload=payload)

class APIProviderError(APIError):
    """Raised when an external API provider encounters an error"""
    def __init__(self, message, payload=None):
        super().__init__(message, status_code=502, payload=payload)

def register_error_handlers(app):
    """Register error handlers for the Flask application"""
    
    @app.errorhandler(APIError)
    def handle_api_error(error):
        """Handle custom API errors"""
        logger.error(f"API Error: {error.message}")
        
        # For API requests (expecting JSON), return JSON response
        if request_wants_json():
            response = jsonify(error.to_dict())
            response.status_code = error.status_code
            return response
        
        # For web requests, render template
        solution_steps = []
        if isinstance(error, APIProviderError):
            solution_steps = [
                "Check that your API key is correct and active",
                "Verify that you have selected the correct model name",
                "Make sure your account has sufficient credits/quota",
                "Check the API provider's status page for any outages"
            ]
        
        return render_template('error.html', 
            error_code=error.status_code,
            error_title="API Error",
            error_message=error.message,
            error_details=str(error.payload) if error.payload else None,
            solution_steps=solution_steps
        ), error.status_code

    @app.errorhandler(HTTPException)
    def handle_http_error(error):
        """Handle HTTP errors"""
        logger.error(f"HTTP Error: {error.description}")
        
        # For API requests (expecting JSON), return JSON response
        if request_wants_json():
            return jsonify({
                'status': 'error',
                'message': error.description,
                'code': error.code
            }), error.code
        
        # For 404 errors, use the existing template
        if error.code == 404:
            return render_template('404.html'), 404
            
        # For other errors, use our generic error template
        return render_template('error.html',
            error_code=error.code,
            error_title="Error",
            error_message=error.description
        ), error.code

    @app.errorhandler(Exception)
    def handle_generic_error(error):
        """Handle unexpected errors"""
        logger.error(f"Unexpected Error: {str(error)}", exc_info=True)
        
        # For API requests (expecting JSON), return JSON response
        if request_wants_json():
            return jsonify({
                'status': 'error',
                'message': 'An unexpected error occurred',
                'code': 500
            }), 500
            
        # For web requests, render template
        return render_template('error.html',
            error_code="500",
            error_title="Server Error",
            error_message="An unexpected error occurred. Please try again later.",
            error_details=str(error) if app.debug else None
        ), 500

    @app.errorhandler(ValidationError)
    def handle_validation_error(error):
        """Handle validation errors"""
        logger.error(f"Validation Error: {error.message}")
        return handle_api_error(error)

    @app.errorhandler(AuthenticationError)
    def handle_authentication_error(error):
        """Handle authentication errors"""
        logger.error(f"Authentication Error: {error.message}")
        return handle_api_error(error)

    @app.errorhandler(AuthorizationError)
    def handle_authorization_error(error):
        """Handle authorization errors"""
        logger.error(f"Authorization Error: {error.message}")
        return handle_api_error(error)

    @app.errorhandler(ResourceNotFoundError)
    def handle_not_found_error(error):
        """Handle resource not found errors"""
        logger.error(f"Resource Not Found: {error.message}")
        return handle_api_error(error)

    @app.errorhandler(APIProviderError)
    def handle_api_provider_error(error):
        """Handle external API provider errors"""
        logger.error(f"API Provider Error: {error.message}")
        return handle_api_error(error)
        
def request_wants_json():
    """Check if the request expects a JSON response"""
    best = request.accept_mimetypes.best_match(['application/json', 'text/html'])
    return (best == 'application/json' and 
            request.accept_mimetypes[best] > request.accept_mimetypes['text/html']) or \
           request.path.startswith('/api/') 