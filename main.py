import fcntl
import os
from flask import Flask , render_template , request , redirect , url_for
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import docker
import subprocess
import random
import time
import uuid
import secrets
from datetime import datetime, timedelta
from flask_sqlalchemy import SQLAlchemy
from werkzeug.middleware.proxy_fix import ProxyFix
from apscheduler.schedulers.background import BackgroundScheduler
import atexit


app = Flask(__name__)
app.wsgi_app = ProxyFix(
    app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1
)

db = SQLAlchemy()


# configuration

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'admin_login'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'
app.secret_key = secrets.token_hex(32)
app.config['SESSION_COOKIE_SECURE'] = False
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
ADMIN_USER = 'change this in production'
ADMIN_PASSWORD_HASH = generate_password_hash('change this in production')
db.init_app(app)

worker_ips = {
        'worker1': 'change this in production to your vm ip',
        'worker2': 'change this in production to your vm ip'
    }

# Creating tables

class ActiveInstance(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    challenge_type = db.Column(db.String(50))
    challenge_name = db.Column(db.String(50))
    subdomain = db.Column(db.String(50), unique=True)
    worker_name = db.Column(db.String(50))
    port = db.Column(db.Integer)
    container_id = db.Column(db.String(64))
    expires_at = db.Column(db.DateTime)
    

class ChallengeData(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    challenge_type = db.Column(db.String(50))
    display_name = db.Column(db.String(50))
    challenge_name = db.Column(db.String(50))
    author_user = db.Column(db.String(50))
    internal_port = db.Column(db.Integer)


class User(UserMixin):
    def __init__(self, id):
        self.id = id

# admin auth logic

@login_manager.user_loader
def load_user(user_id):
    if user_id == ADMIN_USER:
        return User(user_id)
    return None

# routing 

@app.route('/')
def index():
    challenges = ChallengeData.query.all()
    active_instances = ActiveInstance.query.all()
    
    status_map = {}
    now = datetime.now()
    
    for inst in active_instances:
        if inst.challenge_name in status_map and status_map[inst.challenge_name]['status'] == 'RUNNING':
            continue

        if inst.container_id == "STOPPED":
             status_map[inst.challenge_name] = {
                'status': 'STOPPED',
                'url': '#',
                'time_left': 'OFFLINE',
                'is_active': False
            }
        else:
            remaining = inst.expires_at - now
            if remaining.total_seconds() > 0:
                minutes_left = int(remaining.total_seconds() // 60)
                if inst.challenge_type == 'netcat':
                    target_ip = worker_ips.get(inst.worker_name, 'Unknown')
                    connection_info = f"nc {target_ip} {inst.port}"
                    link_url = '#'
                else:
                    connection_info = "Join Challenge"
                    link_url = f"http://{inst.subdomain}.{DOMAIN}"
                
                status_map[inst.challenge_name] = {
                    'status': 'RUNNING',
                    'url': f"link_url",
                    'display_text': connection_info,
                    'type': inst.challenge_type,
                    'time_left': f"{minutes_left}m remaining",
                    'is_active': True
                }
            
    return render_template("index.html", challenges=challenges, status_map=status_map)

@app.route('/admin_login')
def admin_login():
    return render_template("admin_login.html")

@app.route('/admin_login',methods=['POST'])
def admin_login_post():
    username = request.form.get('username')
    password = request.form.get('password')
    if username == ADMIN_USER and check_password_hash(ADMIN_PASSWORD_HASH, password):
        user = User(username)
        login_user(user, remember=True)

        return redirect(url_for('admin'))
    return "Invalid credentials"

@app.route('/admin')
@login_required
def admin():
    active_instances = ActiveInstance.query.all()
    return render_template("admin.html", active_instances=active_instances)


@app.route('/create',methods = ['POST'])
@login_required
def create_challenge():
    display_name = request.form.get('display_name')
    challenge_name = request.form.get('challenge_name')
    author_user = request.form.get('author_user')
    internal_port = request.form.get('internal_port')
    challenge_type = request.form.get('challenge_type')

    new_challenge = ChallengeData(
        display_name=display_name,
        challenge_name=challenge_name,
        author_user=author_user,
        challenge_type =challenge_type,
        internal_port=internal_port
    )
    db.session.add(new_challenge)
    db.session.commit()
    return redirect(url_for('admin'))

@app.route('/extend/<challenge_name>')
def extend_challenge(challenge_name):
    instance = ActiveInstance.query.filter_by(challenge_name=challenge_name).first()
    if not instance:
        return redirect(url_for('index'))

    now = datetime.now()

    limit_horizon = now + timedelta(hours=2) 
    

    base_time = max(instance.expires_at, now)
    new_expiry = base_time + timedelta(minutes=30)
    
    if new_expiry > limit_horizon:
        instance.expires_at = limit_horizon
    else:
        instance.expires_at = new_expiry

    db.session.commit()
    return redirect(url_for('index'))

@app.route('/admin/stop/<int:instance_id>')
@login_required
def admin_stop_instance(instance_id):
    instance = ActiveInstance.query.get(instance_id)
    if instance:
        try:
            client = get_docker_client(instance.worker_name)
            if client:
                container = client.containers.get(instance.container_id)
                container.stop()
                container.remove() 
                print(f"Admin terminated container {instance.container_id}")
        except Exception as e:
            print(f"Error stopping container: {e}")

        instance.container_id = "STOPPED"
        instance.expires_at = datetime.now() 
        db.session.commit()
    
    return redirect(url_for('admin'))


# main functions used to create the instances

WORKERS = ['worker1', 'worker2']
DOMAIN = "change this in production to your domain"

def get_docker_client(worker_name):
    worker_connections = {
            'worker1': 'ssh://REDACTED@REDACTED', # change these to your ssh name and ip
            'worker2': 'ssh://REDACTED@REDACTED'
     }
    target_url = worker_connections.get(worker_name)
    return docker.DockerClient(base_url=target_url)

def find_free_port(worker_name):
    port = random.randint(10000,20000)
    active_port = ActiveInstance.query.filter_by(worker_name=worker_name,port=port).first()
    if not active_port:
        return port
    else:
        return find_free_port(worker_name)
    
def deploy_container(challenge_name, subdomain, author_user, internal_port, challenge_type):
    existing = ActiveInstance.query.filter_by(challenge_name=challenge_name).first()

    if existing and existing.challenge_type == 'website':
        existing.expires_at = datetime.now() + timedelta(minutes=30)
        db.session.commit()
        return f"http://{existing.subdomain}.{DOMAIN}"
    
    elif existing and existing.challenge_type == 'netcat':
        existing.expires_at = datetime.now() + timedelta(minutes=30)
        db.session.commit()
        worker_ip = worker_ips[existing.worker_name]
        return f"nc {worker_ip} {existing.port}"
    
    worker = random.choice(WORKERS)
    client = get_docker_client(worker)
    port = find_free_port(worker)

    try:
        container = client.containers.run(
            image=f"{author_user}/{challenge_name}:latest",
            detach=True,
            ports={f'{internal_port}/tcp': port},
            restart_policy={"Name": "always"}
        )
    except Exception as e:
        return f"Error starting container: {str(e)}"
    
    new_instance = ActiveInstance(
        challenge_name=challenge_name,
        subdomain=subdomain,
        worker_name=worker,
        challenge_type=challenge_type,
        port=port,
        container_id=container.id,
        expires_at=datetime.now() + timedelta(minutes=60)
    )
    db.session.add(new_instance)
    db.session.commit()

    if challenge_type == 'website':
        create_nginx_config(subdomain,worker,port)
        reload_nginx()
        return f"http://{subdomain}.{DOMAIN}"
    
    elif challenge_type == 'netcat':
        worker_ip = worker_ips[new_instance.worker_name]
        return f"nc {worker_ip} {new_instance.port}"

# nginx config

def create_nginx_config(subdomain, worker_name,port):
    target_ip = worker_ips[worker_name]

    config = f"""
server {{
    listen 80;
    server_name {subdomain}.{DOMAIN};

    location / {{
        proxy_pass http://{target_ip}:{port};
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }}
}}
    """

    with open(f"/etc/nginx/sites-enabled/{subdomain}.conf", "w") as f:
        f.write(config)

def reload_nginx():
    subprocess.run(["sudo", "/usr/sbin/nginx", "-s", "reload"])


# cleaning up

def cleanup_expired_instances():
    with app.app_context():
        now = datetime.now()

        expired = ActiveInstance.query.filter(
            ActiveInstance.expires_at < now, 
            ActiveInstance.container_id != 'STOPPED'
        ).all()

        if not expired:
            return

        print(f"[{now}] Cleaning up {len(expired)} expired instances...")

        for instance in expired:
            try:
                client = get_docker_client(instance.worker_name)

                if client:
                    try:
                        container = client.containers.get(instance.container_id)
                        container.stop()
                        container.remove()
                        print(f" -> Stopped container {instance.container_id[:8]}")
                    except Exception as e:
                        print(f" -> Container warning (already gone?): {e}")

                instance.container_id = "STOPPED"

            except Exception as e:
                print(f" -> Error cleaning instance {instance.id}: {e}")

        db.session.commit()

# routes for the api

@app.route("/start/<challenge_name>")
def start(challenge_name):
    old_instances = ActiveInstance.query.filter_by(challenge_name=challenge_name).all()
    
    for old in old_instances:
        if old.container_id != "STOPPED":
            try:
                client = get_docker_client(old.worker_name)
                client.containers.get(old.container_id).remove(force=True)
            except:
                pass
        
        db.session.delete(old)
    
    db.session.commit() 

    challenge_data = ChallengeData.query.filter_by(challenge_name=challenge_name).first()
    if not challenge_data:
        return f"Challenge '{ChallengeData.display_name}' not found.", 404

    author_user = challenge_data.author_user
    internal_port = challenge_data.internal_port
    challenge_type = challenge_data.challenge_type

    random_suffix = uuid.uuid4().hex[:8]
    subdomain = f"{challenge_name}-{random_suffix}"
    
    result = deploy_container(challenge_name, subdomain, author_user, internal_port, challenge_type)
    
    if result.startswith("Error"):
        return f"<h3>Deployment Failed</h3><p>{result}</p>", 500
    
    if result.startswith("http"):
        return redirect(result)
    
    return redirect(url_for('index'))


# saving memory by making only 1 gunicorn worker start a scheduler

try:
    _lock_file = open("scheduler.lock", "wb")
    fcntl.lockf(_lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
    
    scheduler = BackgroundScheduler()
    scheduler.add_job(func=cleanup_expired_instances, trigger="interval", seconds=60)
    scheduler.start()
    
    atexit.register(lambda: fcntl.lockf(_lock_file, fcntl.LOCK_UN))
    print(" -> Scheduler started by this worker.")
    
except IOError:
    print(" -> Scheduler skipped (already running in another worker).")


if __name__ == '__main__':
    with app.app_context():
        db.create_all() 
    app.run(host='0.0.0.0', port=5000, debug=False)
