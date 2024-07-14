from app import create_app, db
from app.models import User, URLAnalysis
from flask_cors import CORS

app = create_app()
CORS(app)
@app.shell_context_processor
def make_shell_context():
    return {'db': db, 'User': User, 'URLAnalysis': URLAnalysis}

if __name__ == '__main__':
    app.run(debug=True)
