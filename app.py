from functools import wraps
from flask import Flask, render_template, redirect, url_for, session, request
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, PasswordField, SubmitField, BooleanField, IntegerField, SelectField, DateTimeField
from wtforms.validators import DataRequired, Email, EqualTo
from werkzeug.security import generate_password_hash, check_password_hash
import nmap
import pandas as pd
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from email.mime.text import MIMEText
import os
import threading
from flask_bootstrap import Bootstrap
import concurrent.futures
from flask import jsonify
from flask_migrate import Migrate
from datetime import datetime, timedelta
from apscheduler.schedulers.background import BackgroundScheduler

# 添加一个全局字典来存储每个任务的进度
task_progress = {}
terminate_flags = {} # 用于存储每个任务的终止标志

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'
db = SQLAlchemy(app)
Bootstrap(app)
migrate = Migrate(app, db)

# 全局字典，用于存储任务和线程
tasks_threads = {}

# 安全措施
# 封禁阈值，单位是访问次数
ACCESS_THRESHOLD = 50

# 高危请求模式
DANGEROUS_PATTERNS = [r'/admin', r'password', r'root']

class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    ips = db.Column(db.Text, nullable=False)
    params = db.Column(db.String(120), default='-p- -sV -sT -sU --min-rate=1000', nullable=False)
    send_email = db.Column(db.Boolean, default=False)
    email = db.Column(db.String(120), default='123456@qq.com')
    threads = db.Column(db.Integer, default=20)
    schedule_interval = db.Column(db.Integer, default=0)  # 用于定时任务的时间间隔（分钟）
    next_execution = db.Column(db.DateTime, nullable=True)
    progress = db.Column(db.Float, default=0)
    status = db.Column(db.String(20), default='pending')  # 状态字段
    is_scheduled = db.Column(db.Boolean, default=False)  
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'))  # 添加创建者字段
    creator = db.relationship('User', backref='tasks_created')  # 反向关系

    
class Port(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    task_id = db.Column(db.Integer, db.ForeignKey('task.id'), nullable=False)
    ip = db.Column(db.String(150), nullable=False)
    port = db.Column(db.Integer, nullable=False)
    name = db.Column(db.String(150), nullable=False)
    agree = db.Column(db.String(150), nullable=False) # 新加 协议字段
    banner = db.Column(db.String(150), nullable=False) # 新加 Banner字段

class User(db.Model):
    __tablename__ = "user"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    role = db.Column(db.String(50), nullable=False, default='user')  # 增加角色字段
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'))  # 添加创建者字段
    creator = db.relationship('User', remote_side=[id], backref='created_users')  # 反向关系

class ZEmail(db.Model):
    __tablename__ = "email"
    id = db.Column(db.Integer, primary_key=True)
    host = db.Column(db.String(150),nullable=False, default='user')
    port = db.Column(db.Integer,nullable=False, default=25)
    user = db.Column(db.String(150),nullable=False)
    passwd = db.Column(db.String(150),nullable=False)

class AccessLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150))
    login_time = db.Column(db.DateTime, default=db.func.current_timestamp())
    ip_address = db.Column(db.String(150))
    failed_login_attempts = db.Column(db.Integer, default=0)
    block_until = db.Column(db.DateTime, nullable=True)  # 添加此字段
    request_url = db.Column(db.String(255))  # 新增字段，记录请求的 URL


class LoginForm(FlaskForm):
    username = StringField('用户名', validators=[DataRequired()])
    password = PasswordField('密码', validators=[DataRequired()])
    submit = SubmitField('登录')

class TaskForm(FlaskForm):
    name = StringField('任务名称', validators=[DataRequired()])
    ips = TextAreaField('IP地址', validators=[DataRequired()])
    params = StringField('Nmap 参数', default='-p- -sV -sT -sU --min-rate=1000', validators=[DataRequired()])
    send_email = BooleanField('发送邮件')
    email = StringField('目标邮箱', default='123456@qq.com', validators=[Email()])
    threads = IntegerField('线程数', default=20)
    schedule = IntegerField('执行间隔（分钟）', default=0)  # 移除 DataRequired() 验证器
    created_at = DateTimeField('创建时间', default=datetime.now(), format='%Y-%m-%d %H:%M:%S', render_kw={'readonly': True})
    submit = SubmitField('开始任务')

# 邮箱管理
class EmailForm(FlaskForm):
    host = StringField('SMTP服务器地址',  default='smtp.qq.com', validators=[DataRequired()])
    port = IntegerField('SMTP服务器端口', default=25, validators=[DataRequired()])
    user = StringField('Email账户', validators=[DataRequired()])
    passwd = StringField('Email密码', validators=[DataRequired()])
    submit = SubmitField('修改')

# 用户管理
class UserForm(FlaskForm):
    username = StringField('用户名', validators=[DataRequired()])
    password = PasswordField('密码', validators=[DataRequired(), EqualTo('confirm', message='Passwords must match')])
    confirm = PasswordField('重复密码')
    role = SelectField('角色', choices=[('user', 'User'), ('admin', 'Admin')], default='user')
    submit = SubmitField('提交')

                    
def log_access(username, failed_login_attempts=0):
    ip_address = request.remote_addr
    request_url = request.path
    log_entry = AccessLog(username=username, ip_address=ip_address, failed_login_attempts=failed_login_attempts, request_url=request_url)
    db.session.add(log_entry)
    db.session.commit()



def scan_udp_ports(ip, params, task_id):
    if terminate_flags[task_id]:  # 检查终止标志
        return []
    
    nm = nmap.PortScanner()
    nm.scan(ip, arguments=params)
    
    open_ports = []
    
    with app.app_context():  # 确保在应用上下文内运行
        for host in nm.all_hosts():
            if terminate_flags[task_id]:  # 检查终止标志
                return []
            for proto in nm[host].all_protocols():
                lport = nm[host][proto].keys()
                for port in lport:
                    if nm[host][proto][port]['state'] == 'open':
                        # 检查数据库中是否已经存在相同的端口记录
                        
                        existing_port = Port.query.filter_by(task_id=task_id, ip=ip, port=port, agree=proto).first()  # agree 协议
                        if existing_port is None:  # 如果不存在相同的端口记录
                            port_info = {
                                'task_id': task_id,
                                'ip': ip,
                                'port': port,
                                'name': nm[host][proto][port]['name'],
                                'agree': proto,
                                'banner': nm[host][proto][port]['product']+' '+nm[host][proto][port]['version'],
                            }
                            open_ports.append(port_info)
                            new_port = Port(task_id=task_id, ip=ip, port=port, name=nm[host][proto][port]['name'], agree=proto, banner=nm[host][proto][port]['product']+' '+nm[host][proto][port]['version'])
                            db.session.add(new_port)
                            db.session.commit()
                        else:
                            # 确保所有端口都在 open_ports ,为邮件发送用
                            port_info = {
                                'task_id': task_id,
                                'ip': ip,
                                'port': port,
                                'name': nm[host][proto][port]['name'],
                                'agree': proto,
                                'banner': nm[host][proto][port]['product']+' '+nm[host][proto][port]['version'],
                            }
                            open_ports.append(port_info)
    
    return open_ports

def send_email(to_email, subject, body, attachment):
    email_settings = ZEmail.query.first()
    from_email = email_settings.user
    password = email_settings.passwd
    
    if not os.path.exists(attachment):
        print(f"Attachment {attachment} does not exist, cannot send email.")
        return

    msg = MIMEMultipart()
    msg['From'] = from_email
    msg['To'] = to_email
    msg['Subject'] = subject

    msg.attach(MIMEText(body, 'html'))

    part = MIMEBase('application', 'octet-stream')
    try:
        with open(attachment, 'rb') as file:
            part.set_payload(file.read())
    except FileNotFoundError as e:
        print(f"Error reading attachment: {e}")
        return

    encoders.encode_base64(part)
    part.add_header('Content-Disposition', f'attachment; filename= {os.path.basename(attachment)}')
    msg.attach(part)

    try:
        server = smtplib.SMTP(email_settings.host, int(email_settings.port))
        server.starttls()
        server.login(from_email, password)
        server.sendmail(from_email, to_email, msg.as_string())
        server.quit()
        print("Email sent successfully")
    except Exception as e:
        print(f"Error sending email: {e}")

def run_task(task_id):
    with app.app_context():
        task = Task.query.get(task_id)
        ips = list(set(task.ips.split()))
        params = task.params
        threads = task.threads
        send_email_flag = task.send_email
        target_email = task.email

        results = []

        # 开始任务，更新状态为运行中
        task.progress = 0
        task.status = 'running'
        db.session.commit()

        terminate_flags[task_id] = False

        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            future_to_ip = {executor.submit(scan_udp_ports, ip, params, task_id): ip for ip in ips}
            total_ips = len(ips)
            completed_ips = 0

            for future in concurrent.futures.as_completed(future_to_ip):
                if terminate_flags[task_id]:
                    break

                ip = future_to_ip[future]
                try:
                    data = future.result()
                    results.extend(data)
                except Exception as exc:
                    print(f"{ip} generated an exception: {exc}")
                
                completed_ips += 1
                task.progress = (completed_ips / total_ips) * 100
                db.session.commit()

        # 完成任务，更新状态为完成
        task.status = 'completed' if not terminate_flags[task_id] else 'terminated'
        db.session.commit()

        df = pd.DataFrame(results)
        filename = f"./out/udp_port_scan_{task.id}_results.xlsx"
        df.to_excel(filename, index=False)

        if send_email_flag:
            email_subject = f"Task {task.name} Completed"
            email_body = f"端口扫描任务 '{task.name}' 已执行完成."
            send_email(target_email, email_subject, email_body, filename)

        print(f"Task {task.name} completed")




def calculate_next_run(schedule):
    return schedule + timedelta(hours=24)  # Example: Next run in 24 hours

def clean_expired_blocks():
    with app.app_context():
        now = datetime.now()
        expired_logs = AccessLog.query.filter(AccessLog.block_until < now).all()
        for log in expired_logs:
            log.block_until = None
            log.failed_login_attempts = 0
        db.session.commit()
        
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
            ip_address = request.remote_addr
            access_log = AccessLog.query.filter_by(ip_address=ip_address).first()
            if access_log and access_log.block_until and datetime.now() < access_log.block_until:
                return redirect(url_for('attack_warning'))  # 封禁时间未到，跳转到警告页面
            
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password, form.password.data):
            session['logged_in'] = True
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role
            log_access(user.username)  # 记录成功登录
            return redirect(url_for('index'))
        else:
            ip_address = request.remote_addr
            access_log = AccessLog.query.filter_by(username=form.username.data, ip_address=ip_address).first()
            if access_log:
                access_log.failed_login_attempts += 1
                if access_log.failed_login_attempts > 10:
                    access_log.block_until = datetime.now() + timedelta(minutes=10)  # 封禁10分钟
            else:
                access_log = AccessLog(username=form.username.data, ip_address=ip_address, failed_login_attempts=1, request_url=request.path)
                db.session.add(access_log)
            db.session.commit()
            
            if access_log.failed_login_attempts > 10:
                return redirect(url_for('attack_warning'))  # 跳转到警告页面
                
    return render_template('login.html', form=form)

# 错误页面引导
@app.errorhandler(404)
def page_not_found(e):
    ip_address = request.remote_addr
    request_url = request.path
    log_entry = AccessLog(
        username='Anonymous',  # 或者使用适当的标识符
        ip_address=ip_address,
        failed_login_attempts=0,  # 可以设置为0，因为404错误通常不是登录失败
        request_url=request_url,
        login_time=datetime.now()
    )
    db.session.add(log_entry)
    db.session.commit()
    
    # 返回自定义的404错误页面或响应
    return redirect(url_for('login'))


@app.route('/attack_warning')
def attack_warning():
    return render_template('attack_warning.html')

@app.route('/logout')
@login_required
def logout():
    session.pop('logged_in', None)
    session.pop('user_id', None)
    session.pop('username', None)
    session.pop('role', None)
    return redirect(url_for('login'))


@app.route('/', methods=['GET', 'POST'])
@login_required
def index():
    form = TaskForm()
    if form.validate_on_submit():
        schedule_interval = form.schedule.data  # 获取任务间隔时间（分钟）
        
        if schedule_interval > 0:
            next_execution = datetime.now() + timedelta(minutes=schedule_interval)
            is_scheduled = True
        else:
            next_execution = None  # 0表示只执行一次，不设置 `next_execution`
            is_scheduled = False


        new_task = Task(
            name=form.name.data,
            ips=form.ips.data,
            params=form.params.data,
            send_email=form.send_email.data,
            email=form.email.data,
            threads=form.threads.data,
            schedule_interval=schedule_interval,  # 存储间隔时间
            next_execution=next_execution,
            is_scheduled=is_scheduled,
            created_by=session['user_id']  # 设置创建者为当前登录的用户
        )
        db.session.add(new_task)
        db.session.commit()
        threading.Thread(target=run_task, args=(new_task.id,)).start()
        return redirect(url_for('task_list'))

    return render_template('index.html', form=form)



@app.route('/tasks')
@login_required
def task_list():
    if session.get('role') == 'admin':
        tasks = Task.query.all()
    else:
        tasks = Task.query.filter_by(created_by=session['user_id']).all()
    return render_template('task_list.html', tasks=tasks)


@app.route('/task/<int:task_id>')
@login_required
def task_detail(task_id):
    task = Task.query.get(task_id)
    if not task:
        return redirect(url_for('task_list'))
    ports = Port.query.filter_by(task_id=task_id).all()
    return render_template('task_detail.html', task=task, ports=ports)



@app.route('/terminate_task/<int:task_id>', methods=['POST'])
@login_required
def terminate_task(task_id):
    terminate_flags[task_id] = True  # 设置终止标志
    
    task = Task.query.get(task_id)
    task.status = 'terminated'
    db.session.commit()
    
    return jsonify({'success': True})

@app.route('/execute_task/<int:task_id>', methods=['POST'])
@login_required
def execute_task(task_id):
    task = Task.query.get(task_id)
    if task:
        threading.Thread(target=run_task, args=(task.id,)).start()
        return jsonify({'success': True})
    return jsonify({'success': False})

@app.route('/delete_task/<int:task_id>', methods=['POST'])
@login_required
def delete_task(task_id):
    task = Task.query.get(task_id)
    if task:
        # 删除与任务相关的所有端口记录
        ports = Port.query.filter_by(task_id=task_id).all()
        for port in ports:
            db.session.delete(port)
        # 删除任务
        db.session.delete(task)
        db.session.commit()
        return jsonify({'success': True})
    return jsonify({'success': False})

@app.route('/progress/<int:task_id>')
def task_progress(task_id):
    task = Task.query.get(task_id)
    if task:
        return jsonify({'progress': task.progress})
    return jsonify({'progress': 100})

def is_admin():
    return session.get('role') == 'admin'

@app.route('/users', methods=['GET', 'POST'])
@login_required
def manage_users():
    if not is_admin():
        return redirect(url_for('index'))

    form = UserForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='pbkdf2:sha256')
        new_user = User(
            username=form.username.data,
            password=hashed_password,
            role=form.role.data,
            created_by=session['user_id']  # 设置创建者为当前登录的用户
        )
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('manage_users'))

    users = User.query.filter_by(created_by=session['user_id']).all()
    return render_template('manage_users.html', form=form, users=users)


@app.route('/delete-user/<int:user_id>', methods=['GET','POST'])
@login_required
def delete_user(user_id):
    if session.get('role') != 'admin':
        return redirect(url_for('index'))
    user = User.query.get(user_id)
    if user and user.created_by == session['user_id']:  # 确保只有创建者可以删除
        db.session.delete(user)
        db.session.commit()
    return redirect(url_for('manage_users'))


@app.route('/edit-user/<int:user_id>', methods=['POST'])
@login_required
def edit_user(user_id):
    if session.get('role') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    user = User.query.get(user_id)
    if not user or user.created_by != session['user_id']:  # 确保只有创建者可以编辑
        return jsonify({'error': 'Unauthorized'}), 403
    
    form = UserForm(request.form, obj=user)
    if form.validate():
        user.username = form.username.data
        if form.password.data:
            user.password = generate_password_hash(form.password.data, method='pbkdf2:sha256')
        user.role = form.role.data
        db.session.commit()
        return jsonify({'success': True})
    else:
        return jsonify({'success': False, 'errors': form.errors})

@app.route('/get_user/<int:user_id>', methods=['GET'])
@login_required
def get_user(user_id):
    if session.get('role') != 'admin':
        return redirect(url_for('index'))
    user = User.query.get(user_id)
    if not user or user.created_by != session['user_id']:
        return jsonify({'error': 'Unauthorized'}), 403

    return jsonify({
        'username': user.username,
        'role': user.role
    })


# 邮箱管理
@app.route('/email', methods=['GET', 'POST'])
@login_required
def email_edit():
    if not is_admin():
        return redirect(url_for('index'))

    form = EmailForm()

    # 获取邮箱数据
    if form.validate_on_submit():
        email_settings = ZEmail.query.first()
        print(form.passwd.data)
        if email_settings:
            email_settings.host = form.host.data
            email_settings.port = form.port.data
            email_settings.user = form.user.data
            email_settings.passwd = form.passwd.data
        else:
            new_email = ZEmail(
                host=form.host.data,
                port=form.port.data,
                user=form.user.data,
                passwd=form.passwd.data
            )
            db.session.add(new_email)
        db.session.commit()
    email_setting = ZEmail.query.first()
    return render_template('email.html', form=form, email_setting=email_setting)


@app.route('/access-log')
@login_required
def access_log():
    if session.get('role') != 'admin':
        return redirect(url_for('index'))
    logs = AccessLog.query.all()
    return render_template('access_log.html', logs=logs)

def create_default_admin():
    admin_user = User.query.filter_by(username='admin').first()
    if not admin_user:
        hashed_password = generate_password_hash('admin', method='pbkdf2:sha256')
        new_admin = User(username='admin', password=hashed_password, role='admin',created_by=1)
        db.session.add(new_admin)
        db.session.commit()

# 创建默认邮箱记录
def create_default_email():
    email_info = ZEmail.query.first()
    if not email_info:
        new_email = ZEmail(host='smtp.qq.com', port=25, user='12345.qq.com', passwd='passwd')
        db.session.add(new_email)
        db.session.commit()


def schedule_tasks():
    with app.app_context():
        now = datetime.now()
        print(f"Checking tasks at {now}")

        # 选择那些 is_scheduled 为 True 的任务
        tasks_to_run = Task.query.filter(Task.is_scheduled == True).all()
        print("任务", tasks_to_run)

        for task in tasks_to_run:
            # 检查是否到达任务的执行时间
            if task.next_execution and task.next_execution <= now:
                print(f"Running task {task.id}, {task.name}")
                # 启动任务执行线程
                threading.Thread(target=run_task, args=(task.id,)).start()

                # 更新任务的下一次执行时间
                if task.schedule_interval > 0:
                    task.next_execution = now + timedelta(minutes=task.schedule_interval)
                    task.status = 'scheduled'  # 更新状态为 'scheduled'
                else:
                    task.next_execution = None
                    task.status = 'completed'  # 如果没有定时间隔，设置为完成状态
                
                db.session.commit()



      
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        clean_expired_blocks()  # 启动时清理过期封禁
        create_default_admin()
        create_default_email()
        # 初始化调度器
        scheduler = BackgroundScheduler()
        scheduler.add_job(schedule_tasks, 'interval', minutes=1)
        scheduler.add_job(clean_expired_blocks, 'interval', minutes=10)  # 每10分钟清理一次
        scheduler.start()  # 确保调度器在应用启动时启动
        
        
    app.run(host="0.0.0.0",debug=True)
