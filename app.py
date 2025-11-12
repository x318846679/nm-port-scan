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

# 确保out文件夹的存在
if not os.path.exists("out"):
    os.mkdir("out")
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
    
    # 添加资产和模板关联字段
    asset_id = db.Column(db.Integer, db.ForeignKey('asset.id'), nullable=True)
    template_id = db.Column(db.Integer, db.ForeignKey('scan_template.id'), nullable=True)
    
    # 关系定义
    asset = db.relationship('Asset', foreign_keys=[asset_id])
    template = db.relationship('ScanTemplate', foreign_keys=[template_id])

# 添加资产模型
class Asset(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip = db.Column(db.Text, nullable=False)  # 改为Text以支持多行IP
    name = db.Column(db.String(150), nullable=False)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    creator = db.relationship('User', backref='assets_created')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# 添加参数模板模型
class ScanTemplate(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    params = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    creator = db.relationship('User', backref='scan_templates')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Port(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    task_id = db.Column(db.Integer, db.ForeignKey('task.id'), nullable=False)
    ip = db.Column(db.String(150), nullable=False)
    port = db.Column(db.Integer, nullable=False)
    name = db.Column(db.String(150), nullable=False)
    agree = db.Column(db.String(150), nullable=False) # 新加 协议字段
    banner = db.Column(db.String(150), nullable=False) # 新加 Banner字段
    
    # 添加与Task模型的反向关系
    task = db.relationship('Task', backref=db.backref('ports', lazy=True))

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
    asset = SelectField('选择资产', coerce=int)
    ips = TextAreaField('或手动输入IP地址(多个IP请换行分隔)')
    template = SelectField('选择参数模板', coerce=int)
    params = StringField('或手动输入Nmap参数', default='-p- -sV -sT -sU --min-rate=1000')
    send_email = BooleanField('发送邮件')
    email = StringField('目标邮箱', default='123456@qq.com', validators=[Email()])
    threads = IntegerField('线程数', default=20)
    schedule = IntegerField('执行间隔（分钟）', default=0)  # 移除 DataRequired() 验证器
    created_at = DateTimeField('创建时间', default=datetime.now(), format='%Y-%m-%d %H:%M:%S', render_kw={'readonly': True})
    submit = SubmitField('开始任务')

# 添加资产管理表单，支持多行IP
class AssetForm(FlaskForm):
    ip = TextAreaField('IP地址(多个IP请换行分隔)', validators=[DataRequired()])
    name = StringField('资产名称', validators=[DataRequired()])
    submit = SubmitField('添加资产')

# 添加参数模板表单
class ScanTemplateForm(FlaskForm):
    name = StringField('模板名称', validators=[DataRequired()])
    params = StringField('Nmap参数', validators=[DataRequired()], default='-p- -sV -sT -sU --min-rate=1000')
    description = TextAreaField('描述')
    submit = SubmitField('保存模板')

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


def is_admin():
    return session.get('role') == 'admin'


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

def run_task(task_id):
    with app.app_context():
        task = Task.query.get(task_id)
        # 如果是定时任务，获取最新的资产IP
        if task.is_scheduled:
            # 查找关联的资产（通过任务名称匹配资产名称）
            asset = Asset.query.filter_by(name=task.name, created_by=task.created_by).first()
            if asset:
                # 更新任务的IP为资产的最新IP
                task.ips = asset.ip
                db.session.commit()
        
        # 处理IP列表，支持多行IP输入
        ip_list = []
        for line in task.ips.split('\n'):
            ips = line.strip().split()
            ip_list.extend(ips)
        
        ips = list(set(ip_list))  # 去重
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
            # 统计扫描结果
            total_ports = len(results)
            unique_ips = len(set([r['ip'] for r in results]))
            
            email_subject = f"任务 {task.name} 执行完成"
            email_body = f"""
            <html>
            <body>
                <h2>端口扫描任务完成通知</h2>
                <p><strong>任务名称:</strong> {task.name}</p>
                <p><strong>执行时间:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                <p><strong>扫描参数:</strong> {task.params}</p>
                <p><strong>扫描IP数量:</strong> {len(ips)}</p>
                <p><strong>发现开放端口数量:</strong> {total_ports}</p>
                <p><strong>涉及IP数量:</strong> {unique_ips}</p>
                <p>详细结果请查看附件中的Excel文件。</p>
            </body>
            </html>
            """
            send_email(target_email, email_subject, email_body, filename)

        print(f"Task {task.name} completed")


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
    # 检查是否是获取数据分析的请求
    if request.args.get('action') == 'analytics':
        # 获取所有端口数据用于分析
        all_ports = Port.query.all()

        # 按日期统计端口数量
        port_trend = {}
        service_distribution = {}

        for port in all_ports:
            try:
                # 确保task关系已加载
                if hasattr(port, 'task') and port.task and hasattr(port.task, 'created_at'):
                    # 统计趋势数据
                    date_str = port.task.created_at.strftime('%Y-%m-%d')
                    port_trend[date_str] = port_trend.get(date_str, 0) + 1

                # 统计服务分布
                if hasattr(port, 'name') and port.name:
                    service_name = str(port.name)  # 确保是字符串
                    service_distribution[service_name] = service_distribution.get(service_name, 0) + 1
            except Exception as e:
                print(f"Error processing port data: {e}")
                continue

        return jsonify({
            'port_trend': port_trend,
            'service_distribution': service_distribution
        })
    
    # 扫描概况数据
    if request.args.get('action') == 'overview':
        total_tasks = Task.query.count()
        completed_tasks = Task.query.filter_by(status='completed').count()
        total_ports = Port.query.count()
        
        return jsonify({
            'total_tasks': total_tasks,
            'completed_tasks': completed_tasks,
            'total_ports': total_ports
        })
    
    # IP搜索功能
    if request.args.get('action') == 'search':
        search_ip = request.args.get('ip')
        if search_ip:
            # 获取包含该IP的所有端口记录
            ports = Port.query.filter(Port.ip == search_ip).all()
            
            # 按任务日期统计端口数量
            port_counts_by_date = {}
            dates = []
            
            for port in ports:
                # 通过task_id获取任务信息
                task = Task.query.get(port.task_id)
                if task and task.created_at:
                    date_str = task.created_at.strftime('%Y-%m-%d %H:%M')
                    if date_str not in port_counts_by_date:
                        port_counts_by_date[date_str] = 0
                        dates.append(date_str)
                    port_counts_by_date[date_str] += 1
            
            # 按日期排序
            dates.sort()
            port_counts = [port_counts_by_date[date] for date in dates]
            
            return jsonify({
                'ports': [port.port for port in ports],
                'dates': dates,
                'port_counts': port_counts
            })

    form = TaskForm()
    # 填充资产和模板选择项
    if session.get('role') == 'admin':
        form.asset.choices = [(-1, '不使用资产')] + [(a.id, a.name) for a in Asset.query.all()]
        form.template.choices = [(-1, '不使用模板')] + [(t.id, t.name) for t in ScanTemplate.query.all()]
    else:
        form.asset.choices = [(-1, '不使用资产')] + [(a.id, a.name) for a in Asset.query.filter_by(created_by=session['user_id']).all()]
        form.template.choices = [(-1, '不使用模板')] + [(t.id, t.name) for t in ScanTemplate.query.filter_by(created_by=session['user_id']).all()]

    if form.validate_on_submit():
        # 处理资产选择
        asset_id = None
        if form.asset.data != -1:
            asset = Asset.query.get(form.asset.data)
            ips = asset.ip
            asset_id = asset.id
        else:
            ips = form.ips.data

        # 处理模板选择
        template_id = None
        if form.template.data != -1:
            template = ScanTemplate.query.get(form.template.data)
            params = template.params
            template_id = template.id
        else:
            params = form.params.data

        schedule_interval = form.schedule.data  # 获取任务间隔时间（分钟）

        if schedule_interval > 0:
            next_execution = datetime.now() + timedelta(minutes=schedule_interval)
            is_scheduled = True
        else:
            next_execution = None  # 0表示只执行一次，不设置 `next_execution`
            is_scheduled = False

        new_task = Task(
            name=form.name.data,
            ips=ips,  # 使用选择的资产IP或手动输入的IP
            params=params,  # 使用选择的模板参数或手动输入的参数
            send_email=form.send_email.data,
            email=form.email.data,
            threads=form.threads.data,
            schedule_interval=schedule_interval,  # 存储间隔时间
            next_execution=next_execution,
            is_scheduled=is_scheduled,
            created_by=session['user_id'],  # 设置创建者为当前登录的用户
            asset_id=asset_id,  # 关联资产
            template_id=template_id  # 关联模板
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


@app.route('/execute_task/<int:task_id>', methods=['POST'])
@login_required
def execute_task(task_id):
    task = Task.query.get(task_id)
    if not task:
        return jsonify({'success': False, 'error': '任务不存在'}), 404
    
    # 检查用户权限（普通用户只能执行自己创建的任务，管理员可以执行所有任务）
    if session.get('role') != 'admin' and task.created_by != session['user_id']:
        return jsonify({'success': False, 'error': '权限不足'}), 403
    
    # 启动新线程执行任务
    threading.Thread(target=run_task, args=(task_id,)).start()
    
    return jsonify({'success': True})


@app.route('/terminate_task/<int:task_id>', methods=['POST'])
@login_required
def terminate_task(task_id):
    task = Task.query.get(task_id)
    if not task:
        return jsonify({'success': False, 'error': '任务不存在'}), 404
    
    # 检查用户权限（普通用户只能终止自己创建的任务，管理员可以终止所有任务）
    if session.get('role') != 'admin' and task.created_by != session['user_id']:
        return jsonify({'success': False, 'error': '权限不足'}), 403
    
    # 设置终止标志
    terminate_flags[task_id] = True
    
    # 更新任务状态
    task.status = 'terminated'
    db.session.commit()
    
    return jsonify({'success': True})


@app.route('/progress/<int:task_id>')
@login_required
def get_progress(task_id):
    # 首先检查数据库中的进度
    task = Task.query.get(task_id)
    if task:
        return jsonify({'progress': task.progress})
    
    # 如果数据库中没有找到任务，返回错误
    return jsonify({'error': 'Task not found'}), 404


@app.route('/task/<int:task_id>')
@login_required
def task_detail(task_id):
    task = Task.query.get(task_id)
    if not task:
        return redirect(url_for('task_list'))
    ports = Port.query.filter_by(task_id=task_id).all()
    
    # 将Port对象转换为字典列表，以便JSON序列化
    ports_data = []
    for port in ports:
        ports_data.append({
            'id': port.id,
            'ip': port.ip,
            'port': port.port,
            'name': port.name,
            'agree': port.agree,
            'banner': port.banner
        })
    
    # 获取历史执行记录用于趋势分析
    task_history = []
    if task.asset_id:
        # 如果任务关联了资产，获取同一资产的历史扫描记录
        task_history = Task.query.filter(
            Task.asset_id == task.asset_id
        ).order_by(Task.created_at.desc()).all()
    else:
        # 如果没有关联资产，获取同名任务的历史记录
        task_history = Task.query.filter(
            Task.name == task.name,
            Task.created_by == task.created_by
        ).order_by(Task.created_at.desc()).all()
    
    # 获取历史端口数据用于趋势分析
    history_data = []
    for history_task in task_history:
        port_count = Port.query.filter_by(task_id=history_task.id).count()
        history_data.append({
            'id': history_task.id,
            'name': history_task.name,
            'created_at': history_task.created_at.strftime('%Y-%m-%d %H:%M:%S') if history_task.created_at else None,
            'port_count': port_count
        })
    
    # 如果任务关联了资产，获取上一次扫描结果进行对比
    diff_data = None
    if task.asset_id:
        # 获取同一资产的上一次扫描任务（排除当前任务）
        previous_task = Task.query.filter(
            Task.asset_id == task.asset_id,
            Task.created_at < task.created_at,
            Task.id != task.id
        ).order_by(Task.created_at.desc()).first()
        
        if previous_task:
            diff_data = compare_tasks(previous_task, task)
    else:
        # 如果没有关联资产，查找创建时间早于当前任务的上一次执行记录
        previous_task = None
        for hist_task in task_history:
            if hist_task.id != task.id:
                previous_task = hist_task
                break
                
        if previous_task:
            diff_data = compare_tasks(previous_task, task)
    
    return render_template('task_detail.html', task=task, ports=ports, ports_data=ports_data, diff_data=diff_data, history_data=history_data)


def compare_tasks(previous_task, current_task):
    """比较两个任务的端口扫描结果"""
    # 获取两个任务的端口数据
    previous_ports = Port.query.filter_by(task_id=previous_task.id).all()
    current_ports = Port.query.filter_by(task_id=current_task.id).all()
    
    # 对比数据
    previous_ports_set = set((p.ip, p.port, p.agree) for p in previous_ports)
    current_ports_set = set((p.ip, p.port, p.agree) for p in current_ports)
    
    # 找出新增和减少的端口
    added_ports = current_ports_set - previous_ports_set
    removed_ports = previous_ports_set - current_ports_set
    unchanged_ports = current_ports_set.intersection(previous_ports_set)
    
    # 将Port对象转换为字典
    added_ports_data = []
    for p in current_ports:
        if (p.ip, p.port, p.agree) in added_ports:
            added_ports_data.append({
                'id': p.id,
                'ip': p.ip,
                'port': p.port,
                'name': p.name,
                'agree': p.agree,
                'banner': p.banner
            })
    
    removed_ports_data = []
    for p in previous_ports:
        if (p.ip, p.port, p.agree) in removed_ports:
            removed_ports_data.append({
                'id': p.id,
                'ip': p.ip,
                'port': p.port,
                'name': p.name,
                'agree': p.agree,
                'banner': p.banner
            })
            
    unchanged_ports_data = []
    for p in current_ports:
        if (p.ip, p.port, p.agree) in unchanged_ports:
            unchanged_ports_data.append({
                'id': p.id,
                'ip': p.ip,
                'port': p.port,
                'name': p.name,
                'agree': p.agree,
                'banner': p.banner
            })
    
    return {
        'previous_task': {
            'id': previous_task.id,
            'name': previous_task.name,
            'created_at': previous_task.created_at.strftime('%Y-%m-%d %H:%M:%S') if previous_task.created_at else None
        },
        'added_ports': added_ports_data,
        'removed_ports': removed_ports_data,
        'unchanged_ports': unchanged_ports_data
    }


@app.route('/assets', methods=['GET', 'POST'])
@login_required
def manage_assets():
    form = AssetForm()
    if form.validate_on_submit():
        asset_id = request.form.get('asset_id')
        if asset_id:  # 编辑资产
            asset = Asset.query.get(asset_id)
            if asset and (is_admin() or asset.created_by == session['user_id']):
                asset.ip = form.ip.data
                asset.name = form.name.data
                db.session.commit()
                return redirect(url_for('manage_assets'))
        else:  # 添加新资产
            new_asset = Asset(
                ip=form.ip.data,
                name=form.name.data,
                created_by=session['user_id']
            )
            db.session.add(new_asset)
            db.session.commit()
            return redirect(url_for('manage_assets'))
    
    if is_admin():
        assets = Asset.query.all()
    else:
        assets = Asset.query.filter_by(created_by=session['user_id']).all()
    
    return render_template('assets.html', form=form, assets=assets)


@app.route('/delete_asset/<int:asset_id>', methods=['POST'])
@login_required
def delete_asset(asset_id):
    asset = Asset.query.get(asset_id)
    if asset and (is_admin() or asset.created_by == session['user_id']):
        # 删除资产相关的任务和端口数据
        tasks = Task.query.filter_by(asset_id=asset_id).all()
        for task in tasks:
            ports = Port.query.filter_by(task_id=task.id).all()
            for port in ports:
                db.session.delete(port)
            db.session.delete(task)
        db.session.delete(asset)
        db.session.commit()
    return redirect(url_for('manage_assets'))


@app.route('/templates', methods=['GET', 'POST'])
@login_required
def manage_templates():
    form = ScanTemplateForm()
    if form.validate_on_submit():
        template_id = request.form.get('template_id')
        if template_id:  # 编辑模板
            template = ScanTemplate.query.get(template_id)
            if template and (is_admin() or template.created_by == session['user_id']):
                template.name = form.name.data
                template.params = form.params.data
                template.description = form.description.data
                db.session.commit()
                return redirect(url_for('manage_templates'))
        else:  # 添加新模板
            new_template = ScanTemplate(
                name=form.name.data,
                params=form.params.data,
                description=form.description.data,
                created_by=session['user_id']
            )
            db.session.add(new_template)
            db.session.commit()
            return redirect(url_for('manage_templates'))
    
    if is_admin():
        templates = ScanTemplate.query.all()
    else:
        templates = ScanTemplate.query.filter_by(created_by=session['user_id']).all()
    
    return render_template('templates.html', form=form, templates=templates)


@app.route('/delete_template/<int:template_id>', methods=['POST'])
@login_required
def delete_template(template_id):
    template = ScanTemplate.query.get(template_id)
    if template and (is_admin() or template.created_by == session['user_id']):
        # 删除模板相关的任务
        tasks = Task.query.filter_by(template_id=template_id).all()
        for task in tasks:
            task.template_id = None  # 解除关联而不是删除任务
        db.session.delete(template)
        db.session.commit()
    return redirect(url_for('manage_templates'))


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
        return redirect(url_for('email_edit'))
    
    email_setting = ZEmail.query.first()
    return render_template('email.html', form=form, email_setting=email_setting)


@app.route('/test_email', methods=['POST'])
@login_required
def test_email():
    if not is_admin():
        return jsonify({'success': False, 'error': '权限不足'})
    
    data = request.get_json()
    test_email = data.get('email')
    
    if not test_email:
        return jsonify({'success': False, 'error': '未提供测试邮箱地址'})
    
    try:
        # 获取邮箱配置
        email_settings = ZEmail.query.first()
        if not email_settings:
            return jsonify({'success': False, 'error': '未配置邮箱信息'})
        
        # 创建测试邮件
        msg = MIMEMultipart()
        msg['From'] = email_settings.user
        msg['To'] = test_email
        msg['Subject'] = '端口扫描系统测试邮件'
        
        body = '这是一封测试邮件，用于验证邮箱配置是否正确。'
        msg.attach(MIMEText(body, 'plain'))
        
        # 发送邮件
        server = smtplib.SMTP(email_settings.host, int(email_settings.port))
        server.starttls()
        server.login(email_settings.user, email_settings.passwd)
        server.sendmail(email_settings.user, test_email, msg.as_string())
        server.quit()
        
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/users')
@login_required
def users_list():
    if not is_admin():
        return redirect(url_for('index'))
    
    users = User.query.all()
    form = UserForm()  # 创建表单实例
    return render_template('manage_users.html', users=users, form=form)


@app.route('/create-user', methods=['POST'])
@login_required
def create_user():
    if not is_admin():
        return jsonify({'success': False, 'error': '权限不足'}), 403
    
    form = UserForm()
    if form.validate_on_submit():
        # 检查用户名是否已存在
        existing_user = User.query.filter_by(username=form.username.data).first()
        if existing_user:
            return jsonify({'success': False, 'error': '用户名已存在'}), 400
        
        # 创建新用户
        user = User(
            username=form.username.data,
            password=generate_password_hash(form.password.data),
            role=form.role.data
        )
        db.session.add(user)
        db.session.commit()
        return jsonify({'success': True})
    
    # 表单验证失败，返回错误信息
    errors = {}
    for field, field_errors in form.errors.items():
        errors[field] = field_errors[0]  # 只取第一个错误信息
    return jsonify({'success': False, 'error': '表单验证失败', 'errors': errors}), 400


@app.route('/delete-user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if not is_admin():
        return redirect(url_for('index'))
    
    user = User.query.get(user_id)
    if user and user.id != session.get('user_id'):  # 不能删除自己
        db.session.delete(user)
        db.session.commit()
    
    return redirect(url_for('users_list'))


@app.route('/edit-user/<int:user_id>', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    if not is_admin():
        return jsonify({'success': False, 'error': '权限不足'}), 403
    
    user = User.query.get(user_id)
    if not user:
        return jsonify({'success': False, 'error': '用户不存在'}), 404
    
    form = UserForm(obj=user)
    if form.validate_on_submit():
        user.username = form.username.data
        if form.password.data:  # 如果提供了新密码
            user.password = generate_password_hash(form.password.data)
        user.role = form.role.data
        db.session.commit()
        return jsonify({'success': True})
    
    # 如果是GET请求或者表单验证失败，返回表单页面
    if request.method == 'GET':
        return render_template('edit_user.html', form=form, user=user)
    else:
        # POST但验证失败，返回错误信息
        errors = {}
        for field, field_errors in form.errors.items():
            errors[field] = field_errors[0]  # 只取第一个错误信息
        return jsonify({'success': False, 'error': '表单验证失败', 'errors': errors}), 400


@app.route('/get_user/<int:user_id>')
@login_required
def get_user(user_id):
    if not is_admin():
        return jsonify({'error': '权限不足'}), 403
    
    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': '用户不存在'}), 404
    
    return jsonify({
        'id': user.id,
        'username': user.username,
        'role': user.role
    })


@app.route('/access-log')
@login_required
def access_log():
    if not is_admin():
        return redirect(url_for('index'))
    
    logs = AccessLog.query.order_by(AccessLog.login_time.desc()).all()
    return render_template('access_log.html', logs=logs)


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        
        # 创建默认管理员账户
        admin_user = User.query.filter_by(username='admin').first()
        if not admin_user:
            admin_user = User(
                username='admin',
                password=generate_password_hash('admin'),
                role='admin'
            )
            db.session.add(admin_user)
            db.session.commit()
            print("默认管理员账户已创建: admin/admin")
        
        # 初始化调度器
        scheduler = BackgroundScheduler()
        scheduler.add_job(clean_expired_blocks, 'interval', minutes=10)  # 每10分钟清理一次
        scheduler.start()  # 确保调度器在应用启动时启动
        
    app.run(host="0.0.0.0", debug=True)
