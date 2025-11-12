from functools import wraps
from flask import Flask, render_template, redirect, url_for, session, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, PasswordField, SubmitField, BooleanField, IntegerField, SelectField, DateTimeField
from wtforms.validators import DataRequired, Email, EqualTo
from wtforms import ValidationError
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

class ChangePasswordForm(FlaskForm):
    old_password = PasswordField('旧密码', validators=[DataRequired()])
    new_password = PasswordField('新密码', validators=[DataRequired()])
    confirm_password = PasswordField('确认新密码', validators=[DataRequired()])
    submit = SubmitField('修改密码')
    
    def validate_new_password(self, field):
        if len(field.data) < 8:
            raise ValidationError('密码长度至少8位')
        if not any(c.isupper() for c in field.data):
            raise ValidationError('密码必须包含至少一个大写字母')
        if not any(c.islower() for c in field.data):
            raise ValidationError('密码必须包含至少一个小写字母')
        if not any(c.isdigit() for c in field.data):
            raise ValidationError('密码必须包含至少一个数字')
    
    def validate_confirm_password(self, field):
        if field.data != self.new_password.data:
            raise ValidationError('两次输入的密码不一致')


class TaskForm(FlaskForm):
    name = StringField('任务名称', validators=[DataRequired()])
    ips = TextAreaField('IP地址(多个IP用换行分隔)', validators=[DataRequired()], render_kw={"rows": 5})
    params = StringField('扫描参数', default='-p- -sV -sT -sU --min-rate=1000', validators=[DataRequired()])
    send_email = BooleanField('发送邮件')
    email = StringField('邮箱地址', validators=[Email()])
    threads = IntegerField('线程数', default=20)
    schedule = IntegerField('任务间隔(分钟，0表示只执行一次)', default=0)
    asset = SelectField('选择资产', coerce=int, validators=[DataRequired()])
    template = SelectField('选择模板', coerce=int, validators=[DataRequired()])
    submit = SubmitField('创建任务')


class AssetForm(FlaskForm):
    name = StringField('资产名称', validators=[DataRequired()])
    ip = TextAreaField('IP地址(多个IP用换行分隔)', validators=[DataRequired()], render_kw={"rows": 5})
    submit = SubmitField('保存资产')


class ScanTemplateForm(FlaskForm):
    name = StringField('模板名称', validators=[DataRequired()])
    params = StringField('扫描参数', validators=[DataRequired()])
    description = TextAreaField('描述', render_kw={"rows": 3})
    submit = SubmitField('保存模板')


class EmailForm(FlaskForm):
    host = StringField('SMTP服务器', validators=[DataRequired()])
    port = IntegerField('端口', validators=[DataRequired()])
    user = StringField('用户名', validators=[DataRequired()])
    passwd = PasswordField('密码', validators=[DataRequired()])
    submit = SubmitField('保存配置')


class UserForm(FlaskForm):
    username = StringField('用户名', validators=[DataRequired()])
    password = PasswordField('密码')
    confirm = PasswordField('确认密码', validators=[EqualTo('password', message='密码必须匹配')])
    role = SelectField('角色', choices=[('user', '普通用户'), ('admin', '管理员')], validators=[DataRequired()])
    submit = SubmitField('保存用户')
    
    def validate_username(self, field):
        # 检查用户名是否已存在
        user = User.query.filter_by(username=field.data).first()
        if user:
            raise ValidationError('用户名已存在')


def is_admin():
    return session.get('role') == 'admin'


def log_access(username):
    """记录用户登录日志"""
    ip_address = request.remote_addr
    access_log = AccessLog.query.filter_by(username=username, ip_address=ip_address).first()
    if access_log:
        access_log.failed_login_attempts = 0  # 重置失败次数
        access_log.login_time = datetime.now()
    else:
        access_log = AccessLog(
            username=username,
            ip_address=ip_address,
            failed_login_attempts=0,
            request_url=request.path,
            login_time=datetime.now()
        )
        db.session.add(access_log)
    db.session.commit()


def clean_expired_blocks():
    """清理过期的封禁记录"""
    expired_logs = AccessLog.query.filter(AccessLog.block_until < datetime.now()).all()
    for log in expired_logs:
        db.session.delete(log)
    db.session.commit()


# 路由装饰器
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


def run_task(task_id):
    """执行扫描任务"""
    # 获取任务
    task = Task.query.get(task_id)
    if not task:
        return

    # 更新任务状态
    task.status = 'running'
    db.session.commit()

    # 初始化nmap扫描器
    nm = nmap.PortScanner()
    
    # 分割IP地址
    ips = task.ips.split('\n')
    total_ips = len(ips)
    scanned_ips = 0
    
    try:
        # 执行扫描
        for ip in ips:
            ip = ip.strip()
            if not ip:
                continue
                
            if terminate_flags.get(task_id, False):
                task.status = 'stopped'
                db.session.commit()
                return
                
            try:
                nm.scan(ip, arguments=task.params)
                
                # 保存扫描结果
                for host in nm.all_hosts():
                    if terminate_flags.get(task_id, False):
                        task.status = 'stopped'
                        db.session.commit()
                        return
                        
                    for proto in nm[host].all_protocols():
                        if terminate_flags.get(task_id, False):
                            task.status = 'stopped'
                            db.session.commit()
                            return
                            
                        lport = nm[host][proto].keys()
                        for port in lport:
                            if terminate_flags.get(task_id, False):
                                task.status = 'stopped'
                                db.session.commit()
                                return
                                
                            # 获取端口信息
                            port_info = nm[host][proto][port]
                            new_port = Port(
                                task_id=task.id,
                                ip=host,
                                port=port,
                                name=port_info.get('name', ''),
                                agree=proto,
                                banner=port_info.get('product', '') + ' ' + port_info.get('version', '')
                            )
                            db.session.add(new_port)
                            
                scanned_ips += 1
                task.progress = (scanned_ips / total_ips) * 100
                db.session.commit()
                
            except Exception as e:
                print(f"扫描 {ip} 时出错: {e}")
                continue
                
        # 完成任务
        task.status = 'completed'
        task.progress = 100
        db.session.commit()
        
        # 发送邮件（如果需要）
        if task.send_email and task.email:
            try:
                send_email_notification(task)
            except Exception as e:
                print(f"发送邮件通知时出错: {e}")
                
    except Exception as e:
        task.status = 'failed'
        db.session.commit()
        print(f"执行任务 {task_id} 时出错: {e}")


def send_email_notification(task):
    """发送邮件通知"""
    # 获取邮箱配置
    email_settings = ZEmail.query.first()
    if not email_settings:
        return
        
    # 创建邮件
    msg = MIMEMultipart()
    msg['From'] = email_settings.user
    msg['To'] = task.email
    msg['Subject'] = f'端口扫描任务完成: {task.name}'
    
    # 邮件正文
    body = f"""
    任务名称: {task.name}
    扫描时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
    扫描IP数量: {len(task.ips.split())}
    
    详细结果请登录系统查看。
    """
    msg.attach(MIMEText(body, 'plain'))
    
    # 附加Excel文件
    try:
        ports = Port.query.filter_by(task_id=task.id).all()
        if ports:
            df = pd.DataFrame([{
                'IP': p.ip,
                '端口': p.port,
                '服务': p.name,
                '协议': p.agree,
                'Banner': p.banner
            } for p in ports])
            
            excel_file = f"out/{task.name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
            df.to_excel(excel_file, index=False)
            
            with open(excel_file, "rb") as attachment:
                part = MIMEBase('application', 'octet-stream')
                part.set_payload(attachment.read())
                
            encoders.encode_base64(part)
            part.add_header(
                'Content-Disposition',
                f'attachment; filename= {os.path.basename(excel_file)}'
            )
            msg.attach(part)
    except Exception as e:
        print(f"附加Excel文件时出错: {e}")
    
    # 发送邮件
    server = smtplib.SMTP(email_settings.host, int(email_settings.port))
    server.starttls()
    server.login(email_settings.user, email_settings.passwd)
    server.sendmail(email_settings.user, task.email, msg.as_string())
    server.quit()


# 路由定义
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password, form.password.data):
            # 检查是否使用默认密码登录
            default_password_hash = generate_password_hash('admin')
            is_default_password = check_password_hash(default_password_hash, form.password.data) and user.username == 'admin'
            
            session['logged_in'] = True
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role
            log_access(user.username)  # 记录成功登录
            
            # 如果是使用默认密码登录，要求修改密码
            if is_default_password:
                return redirect(url_for('change_password'))
                
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


@app.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    form = ChangePasswordForm()
    if form.validate_on_submit():
        user = User.query.get(session['user_id'])
        if user:
            # 验证旧密码
            if check_password_hash(user.password, form.old_password.data):
                # 检查新密码强度
                new_password = form.new_password.data
                if len(new_password) < 8:
                    flash('密码长度至少8位', 'error')
                elif not any(c.isupper() for c in new_password):
                    flash('密码必须包含至少一个大写字母', 'error')
                elif not any(c.islower() for c in new_password):
                    flash('密码必须包含至少一个小写字母', 'error')
                elif not any(c.isdigit() for c in new_password):
                    flash('密码必须包含至少一个数字', 'error')
                else:
                    # 更新密码
                    user.password = generate_password_hash(new_password)
                    db.session.commit()
                    flash('密码修改成功', 'success')
                    return redirect(url_for('index'))
            else:
                flash('旧密码错误', 'error')
        else:
            flash('用户不存在', 'error')
    
    return render_template('change_password.html', form=form)


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
    # 显示所有任务列表
    if session.get('role') == 'admin':
        tasks = Task.query.all()
    else:
        tasks = Task.query.filter_by(created_by=session['user_id']).all()
    return render_template('task_list.html', tasks=tasks)


@app.route('/task/<int:task_id>')
@login_required
def task_detail(task_id):
    # 显示特定任务的详细信息
    task = Task.query.get_or_404(task_id)
    
    # 检查权限：管理员可以查看所有任务，普通用户只能查看自己的任务
    if session.get('role') != 'admin' and task.created_by != session['user_id']:
        return redirect(url_for('task_list'))
    
    # 获取任务相关的端口数据
    ports = Port.query.filter_by(task_id=task_id).all()
    
    # 将端口数据按IP分组
    ports_by_ip = {}
    for port in ports:
        if port.ip not in ports_by_ip:
            ports_by_ip[port.ip] = []
        ports_by_ip[port.ip].append(port)
    
    return render_template('task_detail.html', task=task, ports_by_ip=ports_by_ip)


@app.route('/delete_task/<int:task_id>', methods=['POST'])
@login_required
def delete_task(task_id):
    task = Task.query.get_or_404(task_id)
    
    # 检查权限：管理员可以删除所有任务，普通用户只能删除自己的任务
    if session.get('role') != 'admin' and task.created_by != session['user_id']:
        return redirect(url_for('task_list'))
    
    # 删除任务相关的端口数据
    ports = Port.query.filter_by(task_id=task_id).all()
    for port in ports:
        db.session.delete(port)
    
    # 删除任务
    db.session.delete(task)
    db.session.commit()
    
    return redirect(url_for('task_list'))


@app.route('/stop_task/<int:task_id>', methods=['POST'])
@login_required
def stop_task(task_id):
    task = Task.query.get_or_404(task_id)
    
    # 检查权限：管理员可以停止所有任务，普通用户只能停止自己的任务
    if session.get('role') != 'admin' and task.created_by != session['user_id']:
        return redirect(url_for('task_list'))
    
    # 设置终止标志
    terminate_flags[task_id] = True
    
    # 更新任务状态
    task.status = 'stopped'
    db.session.commit()
    
    return redirect(url_for('task_list'))


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
        return redirect(url_for('index'))
    
    user = User.query.get(user_id)
    if not user:
        return redirect(url_for('users_list'))
    
    form = UserForm(obj=user)
    if form.validate_on_submit():
        user.username = form.username.data
        if form.password.data:  # 如果提供了新密码
            user.password = generate_password_hash(form.password.data)
        user.role = form.role.data
        db.session.commit()
        return redirect(url_for('users_list'))
    
    return render_template('edit_user.html', form=form, user=user)


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
    
    # 获取所有访问日志，按登录时间倒序排列
    logs = AccessLog.query.order_by(AccessLog.login_time.desc()).all()
    return render_template('access_log.html', logs=logs)


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
        scheduler.add_job(func=clean_expired_blocks, trigger="interval", minutes=1)
        scheduler.start()
        
    app.run(debug=True, host='0.0.0.0')