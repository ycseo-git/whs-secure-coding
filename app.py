import sqlite3
import uuid
from flask import Flask, render_template, request, redirect, url_for, session, flash, g
from flask_socketio import SocketIO, send
from flask_wtf.csrf import CSRFProtect # CSRF 보호
from flask import Flask, session # Session

app = Flask(__name__)
# 세션 보안 설정 추가
app.config['SESSION_COOKIE_HTTPONLY'] = True  # 자바스크립트에서 세션 쿠키를 접근할 수 없게
app.config['SESSION_COOKIE_SECURE'] = True    # HTTPS 환경에서만 세션 쿠키 전송

# 앱을 시작할 때 사용하는 secret_key 설정
app.secret_key = 'your_secret_key_here'  # 안전한 키를 설정

app.config['SECRET_KEY'] = 'secret!'
csrf = CSRFProtect(app) # CSRF 보호
DATABASE = 'market.db'
socketio = SocketIO(app)

# 데이터베이스 연결 관리: 요청마다 연결 생성 후 사용, 종료 시 close
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row  # 결과를 dict처럼 사용하기 위함
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

# 테이블 생성 (최초 실행 시에만)
def init_db():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        # 사용자 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                bio TEXT,
                is_active INTEGER DEFAULT 1,
                is_admin INTEGER DEFAULT 0,
                balance INTEGER DEFAULT 10000
            )
        """)
        # 상품 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS product (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                price TEXT NOT NULL,
                seller_id TEXT NOT NULL,
                is_deleted INTEGER DEFAULT 0
            )
        """)
        # 신고 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS report (
                id TEXT PRIMARY KEY,
                reporter_id TEXT NOT NULL,
                target_id TEXT NOT NULL,
                reason TEXT NOT NULL
            )
        """)
        # 채팅 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS chat (
                id TEXT PRIMARY KEY,
                sender_id TEXT NOT NULL,
                receiver_id TEXT NOT NULL,
                message TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        # 채팅방 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS chat_room (
                id TEXT PRIMARY KEY,
                user1 TEXT NOT NULL,
                user2 TEXT NOT NULL
            )
        """)

        db.commit()

# 기본 라우트
@app.route('/')
@app.route('/')
def index():
    try:
        if 'user_id' in session:
            db = get_db()
            cursor = db.cursor()
            cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
            user = cursor.fetchone()
        else:
            user = None  # 로그인하지 않은 경우 user = None

        return render_template('index.html', user=user)

    except Exception as e:
        app.logger.error(f"Error: {e}")
        flash("처리 중 오류가 발생했습니다.")
        return redirect(url_for('index'))

# @app.route('/')
# def index():
#     if 'user_id' in session:
#         return redirect(url_for('dashboard'))
#     return render_template('index.html')

# 회원가입
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        try:
            username = request.form['username']
            password = request.form['password']
            
            # 아이디 길이 및 공백 체크
            if len(username) < 3 or len(username) > 30:
                flash("아이디는 3~30자여야 합니다.")
                return redirect(url_for('register'))

            # 비밀번호 길이 체크
            if len(password) < 6:
                flash("비밀번호는 최소 6자 이상이어야 합니다.")
                return redirect(url_for('register'))

            db = get_db()
            cursor = db.cursor()
            cursor.execute("SELECT * FROM user WHERE username = ?", (username,))
            if cursor.fetchone() is not None:
                flash('이미 존재하는 사용자명입니다.')
                return redirect(url_for('register'))

            user_id = str(uuid.uuid4())  # 유니크한 ID 생성
            cursor.execute("INSERT INTO user (id, username, password, is_active) VALUES (?, ?, ?, ?)",
                           (user_id, username, password, 1))
            db.commit()

            flash("회원가입 성공! 로그인 해주세요.")
            return redirect(url_for('login'))

        except Exception as e:
            app.logger.error(f"Error: {e}")  # 서버에서만 상세 오류 로그
            flash("처리 중 오류가 발생했습니다.")
            return redirect(url_for('register'))
    return render_template('register.html')

# @app.route('/register', methods=['GET', 'POST'])
# def register():
#     if request.method == 'POST':
#         username = request.form['username']
#         password = request.form['password']

#         # 아이디 길이 및 공백 체크
#         if len(username) < 3 or len(username) > 30:
#             flash("아이디는 3~30자여야 합니다.")
#             return redirect(url_for('register'))

#         # 비밀번호 길이 체크
#         if len(password) < 6:
#             flash("비밀번호는 최소 6자 이상이어야 합니다.")
#             return redirect(url_for('register'))

#         db = get_db()
#         cursor = db.cursor()
#         # 중복 사용자 체크
#         cursor.execute("SELECT * FROM user WHERE username = ?", (username,))
#         if cursor.fetchone() is not None:
#             flash('이미 존재하는 사용자명입니다.')
#             return redirect(url_for('register'))

#         # 사용자 저장
#         user_id = str(uuid.uuid4())  # 유니크한 ID 생성
#         cursor.execute("INSERT INTO user (id, username, password, is_active) VALUES (?, ?, ?, ?)",
#                        (user_id, username, password, 1))
#         db.commit()

#         flash("회원가입 성공! 로그인 해주세요.")
#         return redirect(url_for('login'))

#     return render_template('register.html')

# @app.route('/register', methods=['GET', 'POST'])
# def register():
#     if request.method == 'POST':
#         username = request.form['username']
#         password = request.form['password']
#         db = get_db()
#         cursor = db.cursor()
#         # 중복 사용자 체크
#         cursor.execute("SELECT * FROM user WHERE username = ?", (username,))
#         if cursor.fetchone() is not None:
#             flash('이미 존재하는 사용자명입니다.')
#             return redirect(url_for('register'))
#         user_id = str(uuid.uuid4())
#         cursor.execute("INSERT INTO user (id, username, password) VALUES (?, ?, ?)",
#                        (user_id, username, password))
#         db.commit()
#         flash('회원가입이 완료되었습니다. 로그인 해주세요.')
#         return redirect(url_for('login'))
#     return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        try:
            username = request.form['username']
            password = request.form['password']

            db = get_db()
            cursor = db.cursor()
            cursor.execute("SELECT * FROM user WHERE username = ? AND password = ?", (username, password))
            user = cursor.fetchone()

            if user:
                if user['is_active'] == 0:
                    flash("휴면 계정입니다. 관리자에게 문의하세요. ycseo@cau.ac.kr")
                    return redirect(url_for('login'))

                session['user_id'] = user['id']
                flash("로그인 성공!")
                return redirect(url_for('dashboard'))
            else:
                flash("아이디 또는 비밀번호가 잘못되었습니다.")

        except Exception as e:
            app.logger.error(f"Error: {e}")  # 서버에서만 상세 오류 로그
            flash("처리 중 오류가 발생했습니다.")
            return redirect(url_for('login'))

    return render_template('login.html')


# @app.route('/login', methods=['GET', 'POST'])
# def login():
#     if request.method == 'POST':
#         username = request.form['username']
#         password = request.form['password']
#         db = get_db()
#         cursor = db.cursor()
#         cursor.execute("SELECT * FROM user WHERE username = ? AND password = ?", (username, password))
#         user = cursor.fetchone()

#         if user:
#             if user['is_active'] == 0:
#                 flash("휴면 계정입니다. 관리자에게 메일을 보내 계정 해제를 요청해주세요. (ycseo@cau.ac.kr)")
#                 return redirect(url_for('login'))

#             session['user_id'] = user['id']
#             flash('로그인 성공!')
#             return redirect(url_for('dashboard'))
#         else:
#             flash('아이디 또는 비밀번호가 올바르지 않습니다.')
#             return redirect(url_for('login'))

#     return render_template('login.html')

# 로그아웃
@app.route('/logout')
def logout():
    try:
        session.pop('user_id', None)
        flash("로그아웃 되었습니다.")
        return redirect(url_for('index'))
    except Exception as e:
        app.logger.error(f"Error: {e}")  # 서버에서만 상세 오류 로그
        flash("처리 중 오류가 발생했습니다.")
        return redirect(url_for('index'))

# @app.route('/logout')
# def logout():
#     session.pop('user_id', None)
#     flash('로그아웃되었습니다.')
#     return redirect(url_for('index'))

# 대시보드: 사용자 정보와 전체 상품 리스트 표시
@app.route('/dashboard')
def dashboard():
    try:
        if 'user_id' not in session:
            return redirect(url_for('login'))

        db = get_db()
        cursor = db.cursor()
        
        # 로그인한 사용자 정보 가져오기
        cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
        user = cursor.fetchone()

        # 검색어 처리
        q = request.args.get('q', '').strip()

        if q:
            cursor.execute("""
                SELECT * FROM product 
                WHERE is_deleted = 0 AND (title LIKE ? OR description LIKE ?)
                ORDER BY rowid DESC
            """, (f"%{q}%", f"%{q}%"))
        else:
            cursor.execute("SELECT * FROM product WHERE is_deleted = 0 ORDER BY rowid DESC")

        products = cursor.fetchall()

        return render_template('dashboard.html', user=user, products=products)
    
    except Exception as e:
        app.logger.error(f"Error: {e}")  # 서버에서만 상세 오류 로그
        flash("처리 중 오류가 발생했습니다.")
        return redirect(url_for('dashboard'))

# @app.route('/dashboard')
# def dashboard():
#     try:
#         if 'user_id' not in session:
#             return redirect(url_for('login'))

#         db = get_db()
#         cursor = db.cursor()
#         cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
#         user = cursor.fetchone()
#         products = cursor.execute("SELECT * FROM product WHERE is_deleted = 0 ORDER BY rowid DESC").fetchall()

#         return render_template('dashboard.html', user=user, products=products)
    
#     except Exception as e:
#         app.logger.error(f"Error: {e}")  # 서버에서만 상세 오류 로그
#         flash("처리 중 오류가 발생했습니다.")
#         return redirect(url_for('dashboard'))

# @app.route('/dashboard')
# def dashboard():
#     if 'user_id' not in session:
#         return redirect(url_for('login'))

#     db = get_db()
#     cursor = db.cursor()

#     # 로그인한 사용자 정보 가져오기
#     cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
#     user = cursor.fetchone()

#     # 검색어 처리
#     q = request.args.get('q', '').strip()

#     if q:
#         cursor.execute("""
#             SELECT * FROM product 
#             WHERE is_deleted = 0 AND (title LIKE ? OR description LIKE ?)
#             ORDER BY rowid DESC
#         """, (f"%{q}%", f"%{q}%"))
#     else:
#         cursor.execute("SELECT * FROM product WHERE is_deleted = 0 ORDER BY rowid DESC")

#     products = cursor.fetchall()

#     return render_template('dashboard.html', products=products, user=user)

# 프로필 페이지: bio 업데이트 가능
@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    db = get_db()
    cursor = db.cursor()

    # POST 요청 처리
    if request.method == 'POST':
        if request.form.get('action') == 'change_password':
            current_password = request.form.get('current_password', '')
            new_password = request.form.get('new_password', '')

            cursor.execute("SELECT password FROM user WHERE id = ?", (session['user_id'],))
            row = cursor.fetchone()
            if row and row['password'] == current_password:
                cursor.execute("UPDATE user SET password = ? WHERE id = ?", (new_password, session['user_id']))
                db.commit()
                flash('비밀번호가 변경되었습니다.')
            else:
                flash('현재 비밀번호가 올바르지 않습니다.')
            return redirect(url_for('profile'))

        # 기존 bio 업데이트 처리
        bio = request.form.get('bio', '')
        cursor.execute("UPDATE user SET bio = ? WHERE id = ?", (bio, session['user_id']))
        db.commit()
        flash('프로필이 업데이트되었습니다.')
        return redirect(url_for('profile'))

    # 사용자 정보 로드
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    current_user = cursor.fetchone()
    return render_template('profile.html', user=current_user)

# 상품 등록
from forms import NewProductForm

@app.route('/new_product', methods=['GET', 'POST'])
def new_product():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    form = NewProductForm()

    if form.validate_on_submit():
        title = form.title.data
        price = form.price.data
        description = form.description.data

        db = get_db()
        cursor = db.cursor()
        product_id = str(uuid.uuid4())

        cursor.execute("INSERT INTO product (id, title, price, description, seller_id) VALUES (?, ?, ?, ?, ?)",
                       (product_id, title, price, description, session['user_id']))
        db.commit()

        flash("상품 등록이 완료되었습니다.")
        return redirect(url_for('dashboard'))

    return render_template('new_product.html', form=form)

# @app.route('/new_product', methods=['GET', 'POST'])
# def new_product():
#     if 'user_id' not in session:
#         return redirect(url_for('login'))

#     if request.method == 'POST':
#         title = request.form['title']
#         price = request.form['price']
#         description = request.form['description']

#         # 제목 길이 및 공백 체크
#         if not title or len(title) > 100:
#             flash("제목은 1~100자여야 합니다.")
#             return redirect(url_for('new_product'))

#         # 가격 양수 체크
#         if not price.isdigit() or int(price) <= 0:
#             flash("가격은 양의 정수여야 합니다.")
#             return redirect(url_for('new_product'))

#         # 설명 길이 체크
#         if not description or len(description) > 1000:
#             flash("설명은 필수이며 1000자 이하로 입력하세요.")
#             return redirect(url_for('new_product'))

#         db = get_db()
#         cursor = db.cursor()

#         # 상품 등록
#         product_id = str(uuid.uuid4())  # 유니크한 상품 ID 생성
#         cursor.execute("INSERT INTO product (id, title, price, description, seller_id) VALUES (?, ?, ?, ?, ?)",
#                        (product_id, title, price, description, session['user_id']))
#         db.commit()

#         flash("상품 등록이 완료되었습니다.")
#         return redirect(url_for('dashboard'))

#     return render_template('new_product.html')

# def new_product():
#     if 'user_id' not in session:
#         return redirect(url_for('login'))
#     if request.method == 'POST':
#         title = request.form['title']
#         description = request.form['description']
#         price = request.form['price']
#         db = get_db()
#         cursor = db.cursor()
#         product_id = str(uuid.uuid4())
#         cursor.execute(
#             "INSERT INTO product (id, title, description, price, seller_id) VALUES (?, ?, ?, ?, ?)",
#             (product_id, title, description, price, session['user_id'])
#         )
#         db.commit()
#         flash('상품이 등록되었습니다.')
#         return redirect(url_for('dashboard'))
#     return render_template('new_product.html')

# 상품 상세보기
@app.route('/product/<product_id>')
def view_product(product_id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM product WHERE id = ?", (product_id,))
    product = cursor.fetchone()
    if not product:
        flash('상품을 찾을 수 없습니다.')
        return redirect(url_for('dashboard'))
    # 판매자 정보 조회
    cursor.execute("SELECT * FROM user WHERE id = ?", (product['seller_id'],))
    seller = cursor.fetchone()
    return render_template('view_product.html', product=product, seller=seller)

# 신고하기
@app.route('/report', methods=['POST'])
def report():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    target_id = request.form['target_id']
    reason = request.form['reason']

    db = get_db()
    cursor = db.cursor()
    report_id = str(uuid.uuid4())
    cursor.execute(
        "INSERT INTO report (id, reporter_id, target_id, reason) VALUES (?, ?, ?, ?)",
        (report_id, session['user_id'], target_id, reason)
    )
    db.commit()
    flash('신고가 접수되었습니다.')
    return redirect(url_for('dashboard'))

# @app.route('/report', methods=['GET', 'POST'])
# def report():
#     if 'user_id' not in session:
#         return redirect(url_for('login'))
#     if request.method == 'POST':
#         target_id = request.form['target_id']
#         reason = request.form['reason']
#         db = get_db()
#         cursor = db.cursor()
#         report_id = str(uuid.uuid4())
#         cursor.execute(
#             "INSERT INTO report (id, reporter_id, target_id, reason) VALUES (?, ?, ?, ?)",
#             (report_id, session['user_id'], target_id, reason)
#         )
#         db.commit()
#         flash('신고가 접수되었습니다.')
#         return redirect(url_for('dashboard'))
#     return render_template('report.html')

# 실시간 채팅: 클라이언트가 메시지를 보내면 전체 브로드캐스트
@socketio.on('send_message')
def handle_send_message_event(data):
    data['message_id'] = str(uuid.uuid4())
    send(data, broadcast=True)

# 내 상품 목록
@app.route('/my-products')
def my_products():
    if 'user_id' not in session:
        return redirect('/login')
    
    db = get_db()
    cursor = db.cursor()

    user_id = session['user_id']
    cursor.execute("SELECT * FROM product WHERE seller_id = ? AND is_deleted = 0", (user_id,))
    products = cursor.fetchall()
    return render_template('my_products.html', products=products)

# 상품 삭제 (soft-delete)
@app.route('/delete-product/<product_id>', methods=['POST'])
def delete_product(product_id):
    if 'user_id' not in session:
        return redirect('/login')

    db = get_db()
    cursor = db.cursor()

    # 소유자 확인
    cursor.execute("SELECT seller_id FROM product WHERE id = ?", (product_id,))
    row = cursor.fetchone()
    if not row or row['seller_id'] != session['user_id']:
        return "권한 없음", 403

    # soft delete
    cursor.execute("UPDATE product SET is_deleted = 1 WHERE id = ?", (product_id,))
    db.commit()
    return redirect('/my-products')

@app.route('/admin/products')
def admin_products():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()

    # 관리자 확인
    cursor.execute("SELECT is_admin FROM user WHERE id = ?", (session['user_id'],))
    user = cursor.fetchone()
    if not user or user['is_admin'] != 1:
        return "접근 권한 없음", 403

    # 신고된 상품 조회 (신고된 상품 ID 기준, 삭제되지 않은 것만)
    cursor.execute('''
        SELECT p.*
        FROM product p
        JOIN report r ON r.target_id = p.id
        WHERE p.is_deleted = 0
        GROUP BY p.id
    ''')
    reported_products = cursor.fetchall()

    return render_template('admin_products.html', products=reported_products)

# 삭제 처리 (관리자용 soft-delete)
@app.route('/admin/delete-product/<product_id>', methods=['POST'])
def admin_delete_product(product_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT is_admin FROM user WHERE id = ?", (session['user_id'],))
    user = cursor.fetchone()
    if not user or user['is_admin'] != 1:
        return "접근 권한 없음", 403

    cursor.execute("UPDATE product SET is_deleted = 1 WHERE id = ?", (product_id,))
    db.commit()
    flash("상품이 삭제되었습니다.")
    return redirect(url_for('admin_products'))

@app.route('/admin/users')
def admin_users():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()

    # 관리자 여부 확인
    cursor.execute("SELECT is_admin FROM user WHERE id = ?", (session['user_id'],))
    user = cursor.fetchone()
    if not user or user['is_admin'] != 1:
        return "접근 권한 없음", 403

    # 신고된 유저 조회 (중복 제거)
    cursor.execute('''
        SELECT u.*
        FROM user u
        JOIN report r ON r.target_id = u.id
        WHERE u.is_active = 1
        GROUP BY u.id
    ''')
    reported_users = cursor.fetchall()

    return render_template('admin_users.html', users=reported_users)

# 휴면 처리
@app.route('/admin/deactivate-user/<user_id>', methods=['POST'])
def deactivate_user(user_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT is_admin FROM user WHERE id = ?", (session['user_id'],))
    user = cursor.fetchone()
    if not user or user['is_admin'] != 1:
        return "접근 권한 없음", 403

    cursor.execute("UPDATE user SET is_active = 0 WHERE id = ?", (user_id,))
    db.commit()
    flash("해당 사용자가 휴면 상태로 전환되었습니다.")
    return redirect(url_for('admin_users'))

@app.route('/users', methods=['GET', 'POST'])
def user_list():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()

    keyword = request.form.get('keyword') if request.method == 'POST' else ''
    users = []

    if keyword:
        cursor.execute("SELECT * FROM user WHERE username LIKE ?", ('%' + keyword + '%',))
        users = cursor.fetchall()

    return render_template('user_list.html', users=users, keyword=keyword)

@app.route('/user/<user_id>', methods=['GET', 'POST'])
def user_detail(user_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()

    cursor.execute("SELECT * FROM user WHERE id = ?", (user_id,))
    user = cursor.fetchone()

    if not user:
        flash('해당 사용자를 찾을 수 없습니다.')
        return redirect(url_for('user_list'))

    return render_template('user_detail.html', target=user)

@app.route('/chat/<receiver_id>', methods=['GET', 'POST'])
def chat(receiver_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()

    sender_id = session['user_id']

    # 메시지 전송
    if request.method == 'POST':
        message = request.form['message']
        chat_id = str(uuid.uuid4())
        cursor.execute('''
            INSERT INTO chat (id, sender_id, receiver_id, message)
            VALUES (?, ?, ?, ?)
        ''', (chat_id, sender_id, receiver_id, message))
        db.commit()

    # 두 사람 사이의 대화 가져오기
    cursor.execute('''
        SELECT * FROM chat
        WHERE (sender_id = ? AND receiver_id = ?)
           OR (sender_id = ? AND receiver_id = ?)
        ORDER BY timestamp
    ''', (sender_id, receiver_id, receiver_id, sender_id))
    messages = cursor.fetchall()

    # 상대 유저 정보 가져오기
    cursor.execute("SELECT * FROM user WHERE id = ?", (receiver_id,))
    other = cursor.fetchone()

    return render_template('chat.html', messages=messages, other=other)

# 상품 수정
@app.route('/edit-product/<product_id>', methods=['GET', 'POST'])
def edit_product(product_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()

    # 본인 소유 상품인지 확인
    cursor.execute("SELECT * FROM product WHERE id = ?", (product_id,))
    product = cursor.fetchone()
    if not product or product['seller_id'] != session['user_id']:
        return "권한 없음", 403

    if request.method == 'POST':
        new_title = request.form['title']
        new_description = request.form['description']
        new_price = request.form['price']
        cursor.execute("""
            UPDATE product
            SET title = ?, description = ?, price = ?
            WHERE id = ?
        """, (new_title, new_description, new_price, product_id))
        db.commit()
        flash('상품이 수정되었습니다.')
        return redirect(url_for('my_products'))

    return render_template('edit_product.html', product=product)

# 물건에서 바로 채팅하기
@app.route('/start-chat/<seller_id>', methods=['POST'])
def start_chat(seller_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    
    if user_id == seller_id:
        flash("본인에게 메시지를 보낼 수 없습니다.")
        return redirect(url_for('dashboard'))

    db = get_db()
    cursor = db.cursor()

    # 기존 채팅방 있는지 확인
    cursor.execute("""
        SELECT id FROM chat_room
        WHERE (user1 = ? AND user2 = ?) OR (user1 = ? AND user2 = ?)
    """, (user_id, seller_id, seller_id, user_id))
    room = cursor.fetchone()

    if room:
        room_id = room['id']
    else:
        import uuid
        room_id = str(uuid.uuid4())
        cursor.execute("INSERT INTO chat_room (id, user1, user2) VALUES (?, ?, ?)",
                       (room_id, user_id, seller_id))
        db.commit()

    return redirect(url_for('chat_room', room_id=room_id))

# @app.route('/start_chat', methods=['POST'])
# def start_chat():
#     if 'user_id' not in session:
#         return redirect(url_for('login'))

#     seller_id = request.form.get('seller_id')
#     if not seller_id:
#         flash("판매자 정보가 올바르지 않습니다.")
#         return redirect(url_for('dashboard'))

#     return redirect(url_for('chat', seller_id=seller_id))

@app.route('/chat-room/<room_id>', methods=['GET', 'POST'])
def chat_room(room_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    db = get_db()
    cursor = db.cursor()

    # 채팅방 정보 조회
    cursor.execute("SELECT * FROM chat_room WHERE id = ?", (room_id,))
    room = cursor.fetchone()
    if not room:
        return "채팅방을 찾을 수 없습니다.", 404

    # 상대방 ID 식별
    current_user = session['user_id']
    other_user = room['user2'] if room['user1'] == current_user else room['user1']

    # 메시지 전송
    if request.method == 'POST':
        msg = request.form['message']
        import uuid
        cursor.execute("""
            INSERT INTO chat (id, sender_id, receiver_id, message)
            VALUES (?, ?, ?, ?)
        """, (str(uuid.uuid4()), current_user, other_user, msg))
        db.commit()
        return redirect(url_for('chat_room', room_id=room_id))

    # 메시지 불러오기
    cursor.execute("""
        SELECT * FROM chat
        WHERE (sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?)
        ORDER BY timestamp
    """, (current_user, other_user, other_user, current_user))
    messages = cursor.fetchall()

    # 상대방 이름 가져오기
    cursor.execute("SELECT username FROM user WHERE id = ?", (other_user,))
    other_user_name = cursor.fetchone()['username']

    return render_template('chat.html',
                           messages=messages,
                           room_id=room_id,
                           other_user=other_user_name)

@app.route('/purchase_product/<product_id>', methods=['POST'])
def purchase_product(product_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()

    # 상품 정보 조회
    cursor.execute("SELECT * FROM product WHERE id = ? AND is_deleted = 0", (product_id,))
    product = cursor.fetchone()

    if not product:
        flash("해당 상품은 존재하지 않거나 비공개 상태입니다.")
        return redirect(url_for('dashboard'))

    # 가격 확인
    price = product['price']
    if not price.isdigit() or int(price) <= 0:
        flash("잘못된 가격입니다.")
        return redirect(url_for('dashboard'))

    # 구매자 잔액 확인
    cursor.execute("SELECT balance FROM user WHERE id = ?", (session['user_id'],))
    buyer_balance = cursor.fetchone()['balance']

    if buyer_balance < int(price):
        flash("잔액이 부족합니다.")
        return redirect(url_for('dashboard'))

    # 구매자 잔액 차감, 판매자 잔액 추가
    cursor.execute("UPDATE user SET balance = balance - ? WHERE id = ?", (price, session['user_id']))
    cursor.execute("UPDATE user SET balance = balance + ? WHERE id = ?", (price, product['seller_id']))
   # ✅ 상품 비활성화
    cursor.execute("UPDATE product SET is_deleted = 1 WHERE id = ?", (product_id,))
    db.commit()
    db.commit()

    flash("상품을 성공적으로 구매했습니다!")
    return redirect(url_for('dashboard'))

# @app.route("/purchase/<product_id>", methods=["POST"])
# def purchase_product(product_id):
#     if 'user_id' not in session:
#         return redirect(url_for('login'))

#     db = get_db()
#     cursor = db.cursor()
#     buyer_id = session['user_id']

#     # 상품 정보 가져오기
#     cursor.execute("SELECT * FROM product WHERE id = ?", (product_id,))
#     product = cursor.fetchone()

#     if product is None or product['is_deleted']:
#         flash("해당 상품이 존재하지 않습니다.")
#         return redirect(url_for("dashboard"))

#     seller_id = product['seller_id']
#     price = int(product['price'])

#     # 자기 자신 물건 구매 방지
#     if buyer_id == seller_id:
#         flash("자신의 상품은 구매할 수 없습니다.")
#         return redirect(url_for("view_product", product_id=product_id))

#     # 구매자 잔액 확인
#     cursor.execute("SELECT balance FROM user WHERE id = ?", (buyer_id,))
#     buyer_balance = cursor.fetchone()['balance']

#     if buyer_balance < price:
#         flash("잔액이 부족합니다.")
#         return redirect(url_for("view_product", product_id=product_id))

#     # 송금 처리
#     cursor.execute("UPDATE user SET balance = balance - ? WHERE id = ?", (price, buyer_id))
#     cursor.execute("UPDATE user SET balance = balance + ? WHERE id = ?", (price, seller_id))
#     db.commit()

#     flash("구매가 완료되었습니다!")
#     return redirect(url_for("dashboard"))

@app.route("/admin")
def admin_dashboard():
    if 'user_id' not in session:
        return redirect(url_for("login"))

    db = get_db()
    cursor = db.cursor()

    # 관리자 여부 확인
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    user = cursor.fetchone()
    if not user or user['is_admin'] != 1:
        return "접근 권한이 없습니다.", 403

    # 전체 유저 조회
    # users = cursor.execute("SELECT id, username, balance, is_admin FROM user").fetchall()
    users = cursor.execute("SELECT id, username, balance, is_admin, is_active FROM user").fetchall()

    # 전체 상품 조회
    products = cursor.execute("""
        SELECT product.id, title, price, seller_id, is_deleted, username AS seller_name
        FROM product
        JOIN user ON product.seller_id = user.id
    """).fetchall()

    return render_template("admin_dashboard.html", users=users, products=products)

@app.route("/admin/toggle_user/<user_id>", methods=["POST"])
def toggle_user_active(user_id):
    if 'user_id' not in session:
        return redirect(url_for("login"))
    
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT is_admin FROM user WHERE id = ?", (session['user_id'],))
    me = cursor.fetchone()
    if not me or me['is_admin'] != 1:
        return "접근 권한 없음", 403

    cursor.execute("SELECT is_active FROM user WHERE id = ?", (user_id,))
    target = cursor.fetchone()
    if target:
        new_value = 0 if target['is_active'] == 1 else 1
        cursor.execute("UPDATE user SET is_active = ? WHERE id = ?", (new_value, user_id))
        db.commit()

    return redirect(url_for("admin_dashboard"))

@app.route("/admin/toggle_product/<product_id>", methods=["POST"])
def toggle_product_deleted(product_id):
    if 'user_id' not in session:
        return redirect(url_for("login"))
    
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT is_admin FROM user WHERE id = ?", (session['user_id'],))
    me = cursor.fetchone()
    if not me or me['is_admin'] != 1:
        return "접근 권한 없음", 403

    cursor.execute("SELECT is_deleted FROM product WHERE id = ?", (product_id,))
    product = cursor.fetchone()
    if product:
        new_value = 0 if product['is_deleted'] == 1 else 1
        cursor.execute("UPDATE product SET is_deleted = ? WHERE id = ?", (new_value, product_id))
        db.commit()

    return redirect(url_for("admin_dashboard"))

if __name__ == '__main__':
    init_db()
    socketio.run(app, debug=True)