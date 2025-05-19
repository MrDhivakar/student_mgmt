import os
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory, abort, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import sqlite3
from functools import wraps
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max upload

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf', 'doc', 'docx'}

# Database initialization
def init_db():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    
    # Create tables if they don't exist
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL,
            school TEXT,
            department TEXT
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS students (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_id TEXT UNIQUE NOT NULL,
            name TEXT NOT NULL,
            email TEXT,
            phone TEXT,
            department TEXT NOT NULL,
            school TEXT NOT NULL,
            photo_path TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS documents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_id TEXT NOT NULL,
            document_name TEXT NOT NULL,
            document_path TEXT NOT NULL,
            upload_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (student_id) REFERENCES students (student_id)
        )
    ''')
    
    # Insert default admin accounts if they don't exist
    default_users = [
        ('superadmin', generate_password_hash('superadmin123'), 'super_admin', None, None),
        ('eng_admin', generate_password_hash('admin123'), 'school', 'Engineering', None),
        ('arts_admin', generate_password_hash('admin123'), 'school', 'Arts', None),
        ('cse_admin', generate_password_hash('admin123'), 'department', 'Engineering', 'CSE'),
        ('eee_admin', generate_password_hash('admin123'), 'department', 'Engineering', 'EEE'),
        ('mech_admin', generate_password_hash('admin123'), 'department', 'Engineering', 'Mech'),
        ('bsc_admin', generate_password_hash('admin123'), 'department', 'Arts', 'B.Sc (CS)'),
        ('bca_admin', generate_password_hash('admin123'), 'department', 'Arts', 'BCA'),
        ('bcom_admin', generate_password_hash('admin123'), 'department', 'Arts', 'B.Com'),
        ('econ_admin', generate_password_hash('admin123'), 'department', 'Arts', 'Economics')
    ]
    
    for user in default_users:
        try:
            cursor.execute('INSERT INTO users (username, password, role, school, department) VALUES (?, ?, ?, ?, ?)', user)
        except sqlite3.IntegrityError:
            pass
    
    # Insert sample students if none exist
    if cursor.execute('SELECT COUNT(*) FROM students').fetchone()[0] == 0:
        sample_students = [
            ('ENG001', 'John Doe', 'john@example.com', '1234567890', 'CSE', 'Engineering', None),
            ('ENG002', 'Jane Smith', 'jane@example.com', '9876543210', 'EEE', 'Engineering', None),
            ('ENG003', 'Bob Johnson', 'bob@example.com', '5551234567', 'Mech', 'Engineering', None),
            ('ART001', 'Alice Brown', 'alice@example.com', '1112223333', 'B.Sc (CS)', 'Arts', None),
            ('ART002', 'Charlie Wilson', 'charlie@example.com', '4445556666', 'BCA', 'Arts', None),
            ('ART003', 'Diana Lee', 'diana@example.com', '7778889999', 'B.Com', 'Arts', None),
            ('ART004', 'Eve Taylor', 'eve@example.com', '0001112222', 'Economics', 'Arts', None)
        ]
        cursor.executemany('''
            INSERT INTO students (student_id, name, email, phone, department, school, photo_path)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', sample_students)
    
    conn.commit()
    conn.close()

init_db()

# Helper functions
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

def login_required(role=None):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'username' not in session:
                return redirect(url_for('login'))
            if role and session.get('role') != role:
                abort(403)
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Routes
@app.route('/')
def home():
    if 'username' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()
        
        if user and check_password_hash(user['password'], password):
            session['username'] = user['username']
            session['role'] = user['role']
            session['school'] = user['school']
            session['department'] = user['department']
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'danger')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required()
def dashboard():
    conn = get_db_connection()
    
    if session['role'] == 'super_admin':
        # Super admin sees all schools and departments
        schools = conn.execute('SELECT DISTINCT school FROM students').fetchall()
        departments = conn.execute('SELECT DISTINCT department FROM students').fetchall()
        total_students = conn.execute('SELECT COUNT(*) FROM students').fetchone()[0]
    elif session['role'] == 'school':
        # School admin sees all departments in their school
        departments = conn.execute('SELECT DISTINCT department FROM students WHERE school = ?', 
                                  (session['school'],)).fetchall()
        total_students = conn.execute('SELECT COUNT(*) FROM students WHERE school = ?', 
                                     (session['school'],)).fetchone()[0]
        schools = [{'school': session['school']}]
    else:
        # Department admin sees only their department
        departments = [{'department': session['department']}]
        total_students = conn.execute('SELECT COUNT(*) FROM students WHERE department = ?', 
                                    (session['department'],)).fetchone()[0]
        schools = [{'school': session['school']}]
    
    # Get recent students (last 5 added)
    recent_students = conn.execute('''
        SELECT student_id, name, department, created_at 
        FROM students 
        ORDER BY created_at DESC 
        LIMIT 5
    ''').fetchall()
    
    conn.close()
    
    return render_template('dashboard.html', 
                         role=session['role'],
                         school=session.get('school'),
                         department=session.get('department'),
                         schools=schools,
                         departments=departments,
                         total_students=total_students,
                         recent_students=recent_students)

@app.route('/api/student_stats')
@login_required()
def student_stats():
    conn = get_db_connection()
    
    # Base query based on role
    if session['role'] == 'super_admin':
        query = '''
            SELECT school, department, COUNT(*) as count 
            FROM students 
            GROUP BY school, department
            ORDER BY school, department
        '''
        stats = conn.execute(query).fetchall()
    elif session['role'] == 'school':
        query = '''
            SELECT department, COUNT(*) as count 
            FROM students 
            WHERE school = ?
            GROUP BY department
            ORDER BY department
        '''
        stats = conn.execute(query, (session['school'],)).fetchall()
    else:
        query = 'SELECT COUNT(*) as count FROM students WHERE department = ?'
        stats = [{'department': session['department'], 'count': conn.execute(query, (session['department'],)).fetchone()['count']}]
    
    conn.close()
    
    # Format for Chart.js
    labels = []
    data = []
    background_colors = []
    
    for stat in stats:
        if 'department' in stat:
            labels.append(stat['department'])
        else:
            labels.append(f"{stat['school']} - {stat['department']}")
        
        data.append(stat['count'])
        
        # Generate colors based on department
        if 'Engineering' in str(stat.get('school', '')):
            background_colors.append('#3B82F6')  # Blue for Engineering
        else:
            background_colors.append('#10B981')  # Green for Arts
    
    return jsonify({
        'labels': labels,
        'data': data,
        'background_colors': background_colors
    })

@app.route('/insert', methods=['GET', 'POST'])
@login_required()
def insert_student():
    if request.method == 'POST':
        student_id = request.form['student_id']
        name = request.form['name']
        email = request.form['email']
        phone = request.form['phone']
        department = request.form['department']
        school = request.form['school']
        photo = request.files['photo']
        
        # Determine allowed schools/departments based on role
        if session['role'] == 'department':
            department = session['department']
            school = session['school']
        elif session['role'] == 'school':
            school = session['school']
        
        # Validate department belongs to school
        conn = get_db_connection()
        valid_dept = conn.execute('SELECT 1 FROM students WHERE school = ? AND department = ? LIMIT 1',
                                (school, department)).fetchone()
        if not valid_dept and session['role'] != 'super_admin':
            conn.close()
            flash('Invalid department for this school', 'danger')
            return redirect(url_for('insert_student'))
        
        # Check if student ID already exists
        existing = conn.execute('SELECT 1 FROM students WHERE student_id = ?', (student_id,)).fetchone()
        if existing:
            conn.close()
            flash('Student ID already exists', 'danger')
            return redirect(url_for('insert_student'))
        
        # Handle photo upload
        photo_path = None
        if photo and allowed_file(photo.filename):
            filename = secure_filename(f"{student_id}_photo.{photo.filename.rsplit('.', 1)[1].lower()}")
            photo_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            photo.save(photo_path)
            photo_path = filename  # Store relative path
        
        # Insert student record
        conn.execute('''
            INSERT INTO students (student_id, name, email, phone, department, school, photo_path)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (student_id, name, email, phone, department, school, photo_path))
        
        conn.commit()
        conn.close()
        
        flash('Student added successfully!', 'success')
        return redirect(url_for('dashboard'))
    
    # For GET request - show form
    conn = get_db_connection()
    
    if session['role'] == 'super_admin':
        schools = conn.execute('SELECT DISTINCT school FROM students').fetchall()
        departments = conn.execute('SELECT DISTINCT department FROM students').fetchall()
    elif session['role'] == 'school':
        schools = [{'school': session['school']}]
        departments = conn.execute('SELECT DISTINCT department FROM students WHERE school = ?',
                                 (session['school'],)).fetchall()
    else:
        schools = [{'school': session['school']}]
        departments = [{'department': session['department']}]
    
    conn.close()
    
    return render_template('insert.html', schools=schools, departments=departments)

@app.route('/search', methods=['GET', 'POST'])
@login_required()
def search_student():
    if request.method == 'POST':
        student_id = request.form['student_id']
        
        conn = get_db_connection()
        
        # Build query based on user role
        query = 'SELECT * FROM students WHERE student_id = ?'
        params = (student_id,)
        
        if session['role'] == 'school':
            query += ' AND school = ?'
            params += (session['school'],)
        elif session['role'] == 'department':
            query += ' AND department = ?'
            params += (session['department'],)
        
        student = conn.execute(query, params).fetchone()
        
        if not student:
            conn.close()
            flash('Student not found or you don\'t have permission to view this student', 'danger')
            return redirect(url_for('search_student'))
        
        # Get documents for this student
        documents = conn.execute('SELECT * FROM documents WHERE student_id = ?', (student_id,)).fetchall()
        
        conn.close()
        
        return render_template('student_details.html', student=student, documents=documents)
    
    return render_template('search.html')

@app.route('/edit/<student_id>', methods=['GET', 'POST'])
@login_required()
def edit_student(student_id):
    conn = get_db_connection()
    
    # First verify the student exists and user has permission
    query = 'SELECT * FROM students WHERE student_id = ?'
    params = (student_id,)
    
    if session['role'] == 'school':
        query += ' AND school = ?'
        params += (session['school'],)
    elif session['role'] == 'department':
        query += ' AND department = ?'
        params += (session['department'],)
    
    student = conn.execute(query, params).fetchone()
    
    if not student:
        conn.close()
        abort(404)
    
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        phone = request.form['phone']
        photo = request.files['photo']
        
        # Handle photo update
        photo_path = student['photo_path']
        if photo and allowed_file(photo.filename):
            # Delete old photo if exists
            if photo_path:
                try:
                    os.remove(os.path.join(app.config['UPLOAD_FOLDER'], photo_path))
                except OSError:
                    pass
            
            # Save new photo
            filename = secure_filename(f"{student_id}_photo.{photo.filename.rsplit('.', 1)[1].lower()}")
            new_photo_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            photo.save(new_photo_path)
            photo_path = filename
        
        # Update student record
        conn.execute('''
            UPDATE students 
            SET name = ?, email = ?, phone = ?, photo_path = ?
            WHERE student_id = ?
        ''', (name, email, phone, photo_path, student_id))
        
        conn.commit()
        conn.close()
        
        flash('Student updated successfully!', 'success')
        return redirect(url_for('search_student'))
    
    # For GET request - show edit form
    conn.close()
    return render_template('edit.html', student=student)

@app.route('/upload_document/<student_id>', methods=['POST'])
@login_required()
def upload_document(student_id):
    if 'document' not in request.files:
        flash('No file selected', 'danger')
        return redirect(url_for('search_student'))
    
    document = request.files['document']
    document_name = request.form.get('document_name', 'Unnamed Document')
    
    if document and allowed_file(document.filename):
        filename = secure_filename(f"{student_id}_{document_name}_{datetime.now().strftime('%Y%m%d%H%M%S')}.{document.filename.rsplit('.', 1)[1].lower()}")
        document_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        document.save(document_path)
        
        conn = get_db_connection()
        
        # Verify student exists and user has permission
        query = 'SELECT 1 FROM students WHERE student_id = ?'
        params = (student_id,)
        
        if session['role'] == 'school':
            query += ' AND school = ?'
            params += (session['school'],)
        elif session['role'] == 'department':
            query += ' AND department = ?'
            params += (session['department'],)
        
        student_exists = conn.execute(query, params).fetchone()
        
        if not student_exists:
            conn.close()
            os.remove(document_path)  # Clean up uploaded file
            abort(403)
        
        # Insert document record
        conn.execute('''
            INSERT INTO documents (student_id, document_name, document_path)
            VALUES (?, ?, ?)
        ''', (student_id, document_name, filename))
        
        conn.commit()
        conn.close()
        
        flash('Document uploaded successfully!', 'success')
    else:
        flash('Invalid file type', 'danger')
    
    return redirect(url_for('search_student', student_id=student_id))

@app.route('/download/<filename>')
@login_required()
def download_file(filename):
    # Verify the user has permission to access this file
    student_id = filename.split('_')[0]
    
    conn = get_db_connection()
    
    query = 'SELECT 1 FROM students WHERE student_id = ?'
    params = (student_id,)
    
    if session['role'] == 'school':
        query += ' AND school = ?'
        params += (session['school'],)
    elif session['role'] == 'department':
        query += ' AND department = ?'
        params += (session['department'],)
    
    student_exists = conn.execute(query, params).fetchone()
    conn.close()
    
    if not student_exists:
        abort(403)
    
    try:
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)
    except FileNotFoundError:
        abort(404)

@app.route('/view_document/<filename>')
@login_required()
def view_document(filename):
    # Similar permission check as download
    student_id = filename.split('_')[0]
    
    conn = get_db_connection()
    
    query = 'SELECT 1 FROM students WHERE student_id = ?'
    params = (student_id,)
    
    if session['role'] == 'school':
        query += ' AND school = ?'
        params += (session['school'],)
    elif session['role'] == 'department':
        query += ' AND department = ?'
        params += (session['department'],)
    
    student_exists = conn.execute(query, params).fetchone()
    conn.close()
    
    if not student_exists:
        abort(403)
    
    # Only allow viewing of certain file types
    ext = filename.rsplit('.', 1)[1].lower()
    if ext not in ['png', 'jpg', 'jpeg', 'gif', 'pdf']:
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)
    
    try:
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename)
    except FileNotFoundError:
        abort(404)

@app.route('/delete_document/<int:doc_id>', methods=['POST'])
@login_required()
def delete_document(doc_id):
    conn = get_db_connection()
    
    # Get document info
    document = conn.execute('SELECT * FROM documents WHERE id = ?', (doc_id,)).fetchone()
    
    if not document:
        conn.close()
        abort(404)
    
    # Verify user has permission to delete this document
    query = 'SELECT 1 FROM students WHERE student_id = ?'
    params = (document['student_id'],)
    
    if session['role'] == 'school':
        query += ' AND school = ?'
        params += (session['school'],)
    elif session['role'] == 'department':
        query += ' AND department = ?'
        params += (session['department'],)
    
    student_exists = conn.execute(query, params).fetchone()
    
    if not student_exists:
        conn.close()
        abort(403)
    
    # Delete file from filesystem
    try:
        os.remove(os.path.join(app.config['UPLOAD_FOLDER'], document['document_path']))
    except OSError:
        pass
    
    # Delete record from database
    conn.execute('DELETE FROM documents WHERE id = ?', (doc_id,))
    conn.commit()
    conn.close()
    
    flash('Document deleted successfully', 'success')
    return redirect(url_for('search_student', student_id=document['student_id']))

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(403)
def forbidden(e):
    return render_template('403.html'), 403

if __name__ == '__main__':
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    app.run(debug=True)