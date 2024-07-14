from flask import Blueprint, request, jsonify, send_file
from flask_jwt_extended import jwt_required, get_jwt_identity, create_access_token
from . import db
from .models import User, URLAnalysis, RevokedTokenModel, MLModel
from .utils import load_model, analyze_url, generate_report

main = Blueprint('main', __name__)

@main.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    user = User(username=data['username'], email=data['email'])
    user.set_password(data['password'])
    db.session.add(user)
    db.session.commit()
    return jsonify({'status': 'success', 'userId': user.id})

@main.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(username=data['username']).first()
    if user and user.check_password(data['password']):
        access_token = create_access_token(identity=user.id)
        return jsonify({'status': 'success', 'token': access_token})
    return jsonify({'status': 'fail', 'message': 'Invalid credentials'})

@main.route('/api/logout', methods=['POST'])
@jwt_required()
def logout():
    jti = get_jwt_identity()  # Get the JWT identity directly
    try:
        revoked_token = RevokedTokenModel(jti=jti)
        db.session.add(revoked_token)
        db.session.commit()
        return jsonify({'status': 'success', 'message': 'Successfully logged out'}), 200
    except Exception as e:
        return jsonify({'status': 'fail', 'message': 'Logout failed: {}'.format(str(e))}), 500


@main.route('/api/analyze', methods=['POST'])
@jwt_required()
def analyze():
    user_id = get_jwt_identity()
    data = request.get_json()
    url = data['url']
    model = load_model()
    probability = analyze_url(model, url)
    analysis = URLAnalysis(url=url, probability=probability, user_id=user_id)
    db.session.add(analysis)
    db.session.commit()
    return jsonify({'status': 'success', 'probability': probability, 'analysis_id': analysis.id})

@main.route('/api/feedback/<int:analysis_id>', methods=['POST'])
@jwt_required()
def feedback(analysis_id):
    data = request.get_json()
    analysis = URLAnalysis.query.get_or_404(analysis_id)
    analysis.feedback = data['feedback']
    db.session.commit()
    return jsonify({'status': 'success', 'message': 'Feedback submitted'})

@main.route('/api/analysis/<int:analysis_id>', methods=['PUT'])
@jwt_required()
def update_analysis(analysis_id):
    data = request.get_json()
    analysis = URLAnalysis.query.get_or_404(analysis_id)
    analysis.url = data['url']
    model = load_model()
    analysis.probability = analyze_url(model, data['url'])
    db.session.commit()
    return jsonify({'status': 'success', 'message': 'Analysis updated'})

@main.route('/api/analysis/<int:analysis_id>', methods=['DELETE'])
@jwt_required()
def delete_analysis(analysis_id):
    analysis = URLAnalysis.query.get_or_404(analysis_id)
    db.session.delete(analysis)
    db.session.commit()
    return jsonify({'status': 'success', 'message': 'Analysis deleted'})


@main.route('/api/history', methods=['GET'])
@jwt_required()
def analysis_history():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    if not user:
        return jsonify({'status': 'fail', 'message': 'User not found'}), 404
    
    analyses = URLAnalysis.query.filter_by(user_id=user_id).all()
    history = []
    for analysis in analyses:
        history.append({
            'id': analysis.id,
            'url': analysis.url,
            'probability': analysis.probability,
            'feedback': analysis.feedback
        })
    
    return jsonify({'status': 'success', 'history': history})



@main.route('/api/model', methods=['POST'])
@jwt_required()
def upload_model():
    if 'modelFile' not in request.files:
        return jsonify({'status': 'fail', 'message': 'No file part in the request'}), 400
    
    file = request.files['modelFile']
    if file.filename == '':
        return jsonify({'status': 'fail', 'message': 'No selected file'}), 400
    
    # Save the model file or handle it as needed
    # Example: Save to a specific directory or store in database
    # For simplicity, let's assume saving to a directory
    model_path = f"{file.filename}"
    file.save(model_path)
    
    # You might want to store the model details in the database
    model = MLModel(model_file=model_path)
    db.session.add(model)
    db.session.commit()
    
    return jsonify({'status': 'success', 'modelId': model.id})

@main.route('/api/model/<int:modelId>', methods=['GET'])
@jwt_required()
def get_model_details(modelId):
    model = MLModel.query.get_or_404(modelId)
    # Assuming you have a method to fetch accuracy and creation timestamp
    model_details = {
        'modelId': model.id,
        'accuracy': model.accuracy,
        'created_at': model.created_at.strftime('%Y-%m-%d %H:%M:%S')
    }
    return jsonify({'status': 'success', 'modelDetails': model_details})

@main.route('/api/analysis/<int:analysisId>/report', methods=['POST'])
@jwt_required()
def generate_analysis_report(analysisId):
    analysis = URLAnalysis.query.get_or_404(analysisId)
    # Generate report content (replace with your actual report generation logic)
    report_content = generate_report(analysis)
    # Assuming generate_report returns a file path, you can send the file back
    return send_file(report_content, as_attachment=True)

@main.route('/api/report/<int:reportId>', methods=['GET'])
@jwt_required()
def get_analysis_report(reportId):
    # Placeholder for fetching report content from storage/database
    # Replace with your actual implementation
    report_content = "Sample report content for report ID {}".format(reportId)
    return jsonify({'status': 'success', 'report': report_content})

