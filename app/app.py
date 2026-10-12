from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from dotenv import load_dotenv
from sqlalchemy.engine import URL
from datetime import datetime
import os
import subprocess
import sys

# --- CONSTANTS ---
REPORT_DIR = 'reports'
RUN_ASSESSMENT_SCRIPT = 'run_assessment.py'

# ----------------------------------------------------
# APPLICATION CONFIGURATION
# ----------------------------------------------------

load_dotenv()
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY') or os.urandom(32)

# MySQL Connection Settings
DB_USER = os.getenv('DB_USER', 'app_user')
DB_PASSWORD = os.getenv('DB_PASSWORD')
DB_HOST = os.getenv('DB_HOST', 'localhost')
DB_NAME = os.getenv('DB_NAME', 'app_data')
if not DB_PASSWORD:
    raise RuntimeError('DB_PASSWORD must be set in .env or environment')

app.config['SQLALCHEMY_DATABASE_URI'] = URL.create(
    'mysql+mysqlconnector', username=DB_USER, password=DB_PASSWORD,
    host=DB_HOST, database=DB_NAME
)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Pagination setting: 12 rows per page as requested
ITEMS_PER_PAGE = 12

# Initialize SQLAlchemy
db = SQLAlchemy(app)

# ----------------------------------------------------
# DATABASE MODEL (Represents the assessment_tests table)
# ----------------------------------------------------

class AssessmentTest(db.Model):
    __tablename__ = 'assessment_tests'

    # Columns defined exactly as in your final CREATE TABLE script
    Id = db.Column(db.Integer, primary_key=True)
    Name = db.Column(db.String(200), nullable=False, unique=True)
    Severity = db.Column(db.String(50), nullable=False)
    Description = db.Column(db.Text)
    SQL_Test = db.Column(db.Text, nullable=False)
    SQL_Detail = db.Column(db.Text)
    Text_Pass = db.Column(db.Text)
    Text_Fail = db.Column(db.Text)
    Status = db.Column(db.String(50), nullable=False, default='Enable')
    Notes = db.Column(db.Text)

    def __repr__(self):
        return f'<AssessmentTest {self.Name}>'

# Ensure tables are created if not already done
with app.app_context():
    db.create_all()

# ----------------------------------------------------
# ROUTES (CRUD Operations)
# ----------------------------------------------------

@app.route('/')
def index():
    return render_template('index.html')

# READ Route: List tests with pagination (Requirement 3)
@app.route('/configure')
@app.route('/configure/<int:page>')
def configure_assessment(page=1):
    pagination = db.paginate(
        db.select(AssessmentTest).order_by(AssessmentTest.Id.asc()),
        page=page,
        per_page=ITEMS_PER_PAGE,
        error_out=False
    )
    return render_template('configure_assessment.html', pagination=pagination)

# CREATE Route: Add a new test (Requirement 4)
@app.route('/test/add', methods=['GET', 'POST'])
def add_test():
    if request.method == 'POST':
        try:
            new_test = AssessmentTest(
                Name = request.form['Name'],
                Severity = request.form['Severity'],
                Description = request.form['Description'],
                SQL_Test = request.form['SQL_Test'],
                SQL_Detail = request.form['SQL_Detail'],
                Text_Pass = request.form['Text_Pass'],
                Text_Fail = request.form['Text_Fail'],
                Status = request.form['Status'],
                Notes = request.form['Notes']
            )
            db.session.add(new_test)
            db.session.commit()
            flash('Assessment test added successfully!', 'success')
            return redirect(url_for('configure_assessment'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error adding test. Details: {str(e)}', 'danger')
            # If error, return form with submitted data
            return render_template('add_edit_test.html', test=request.form, action='Add New Test')

    # GET request: show the empty form
    return render_template('add_edit_test.html', test=None, action='Add New Test')

# UPDATE Route: Edit an existing test (Requirement 3 Detail View)
@app.route('/test/edit/<int:test_id>', methods=['GET', 'POST'])
def edit_test(test_id):
    # Retrieve the test, or return 404 if not found
    test = db.get_or_404(AssessmentTest, test_id)

    if request.method == 'POST':
        try:
            # Update attributes from form data
            test.Name = request.form['Name']
            test.Severity = request.form['Severity']
            test.Description = request.form['Description']
            test.SQL_Test = request.form['SQL_Test']
            test.SQL_Detail = request.form['SQL_Detail']
            test.Text_Pass = request.form['Text_Pass']
            test.Text_Fail = request.form['Text_Fail']
            test.Status = request.form['Status']
            test.Notes = request.form['Notes']

            db.session.commit()
            flash('Assessment test updated successfully!', 'success')
            return redirect(url_for('configure_assessment'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error updating test. Details: {str(e)}', 'danger')
            # Stay on the edit page with current data
            return render_template('add_edit_test.html', test=test, action='Update Test')

    # GET request: show the form pre-filled with test data
    return render_template('add_edit_test.html', test=test, action='Update Test')

# DELETE Route: Delete a test
@app.route('/test/delete/<int:test_id>', methods=['POST'])
def delete_test(test_id):
    try:
        test_to_delete = db.get_or_404(AssessmentTest, test_id)
        test_name = test_to_delete.Name
        db.session.delete(test_to_delete)
        db.session.commit()
        flash(f'Test "{test_name}" deleted successfully.', 'warning')
        return redirect(url_for('configure_assessment'))
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting test. Details: {str(e)}', 'danger')
        return redirect(url_for('configure_assessment'))


# ----------------------------------------------------
# REPORT VIEWING & RUN ASSESSMENT
# ----------------------------------------------------

@app.route('/reports/<path:filename>')
def view_report(filename):
    return send_from_directory(REPORT_DIR, filename)

@app.route('/run_assessment', methods=['GET', 'POST'])
def run_assessment():
    if request.method == 'POST':
        server_ip = request.form.get('server_ip')
        port = request.form.get('port')
        service_name = request.form.get('service_name')
        oracle_user = request.form.get('oracle_user')
        oracle_password = request.form.get('oracle_password')
        report_filename = request.form.get('report_filename')

        # rapor dosyasını formdan gelenle kur
        if not report_filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            report_filename = f"assessment_report_{server_ip.replace('.', '_')}_{timestamp}.html"

        full_report_path = os.path.join(REPORT_DIR, report_filename)

        # Eğer sadece bağlantı testi istenmişse (dry_run)
        if request.form.get('dry_run') == '1':
            connection_status = "FAILED"
            try:
                import oracledb
                dsn = f"{server_ip}:{port}/{service_name}"
                conn = oracledb.connect(user=oracle_user, password=oracle_password, dsn=dsn)
                conn.close()
                connection_status = "SUCCESS"
            except Exception as e:
                connection_status = f"FAILED: {e}"

            return render_template(
                'assessment_preview.html',
                server_ip=server_ip,
                port=port,
                service_name=service_name,
                oracle_user=oracle_user,
                oracle_password=oracle_password,  # sadece hidden field için; ekrana yazmıyoruz
                report_filename=report_filename,
                connection_status="SUCCESS" if connection_status == "SUCCESS" else "FAILED"
            )

        # Tam çalıştırma: subprocess ile mevcut run_assessment.py çağrısı
        try:
            os.makedirs(REPORT_DIR, exist_ok=True)

            cmd = [
                sys.executable,
                RUN_ASSESSMENT_SCRIPT,
                server_ip,
                port,
                service_name,
                full_report_path,
                oracle_user
            ]
            result = subprocess.run(
                cmd, input=oracle_password, capture_output=True,
                text=True, check=False
            )

            if result.returncode != 0:
                error_output = result.stderr if result.stderr else result.stdout
                error_message = f"Assessment failed. Error in {RUN_ASSESSMENT_SCRIPT} script. Output: {error_output}"
                return render_template('error.html', error_message=error_message), 500

            return redirect(url_for('view_report', filename=report_filename))

        except FileNotFoundError:
            error_message = f"Error: Python interpreter ({sys.executable}) or script ({RUN_ASSESSMENT_SCRIPT}) not found."
            return render_template('error.html', error_message=error_message), 500
        except subprocess.CalledProcessError as e:
            error_message = f"Assessment failed due to subprocess error: {e.stderr}"
            return render_template('error.html', error_message=error_message), 500
        except Exception as e:
            error_message = f"An unexpected error occurred: {e}"
            return render_template('error.html', error_message=error_message), 500

    default_report_name = datetime.now().strftime("Assessment-%d-%m-%Y.html")
    return render_template('run_assessment.html', default_report_name=default_report_name)

@app.route('/help')
def help_page():
    return "<h1>Help and Documentation Page</h1>"

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000)
