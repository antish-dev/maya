import os, sqlite3, secrets, time, hashlib, hmac, json
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path
from flask import Flask, request, jsonify, render_template, session, g
from werkzeug.security import generate_password_hash, check_password_hash

BASE=Path(__file__).resolve().parent
DB_PATH=Path(os.environ.get('MAYA_DATABASE', BASE/'data'/'maya.db'))
app=Flask(__name__)
secret=os.environ.get('MAYA_SECRET_KEY')
if not secret or secret=='change-me':
    raise RuntimeError('MAYA_SECRET_KEY must be set to a strong production secret')
app.secret_key=secret
app.config.update(SESSION_COOKIE_SECURE=os.environ.get('MAYA_HTTPS','true').lower()=='true',SESSION_COOKIE_HTTPONLY=True,SESSION_COOKIE_SAMESITE='Lax',PERMANENT_SESSION_LIFETIME=1800,MAX_CONTENT_LENGTH=1024*1024)

SCHEMA='''
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY,email TEXT UNIQUE NOT NULL,name TEXT NOT NULL,role TEXT NOT NULL CHECK(role IN ('ceo','hr','manager','employee','partner','auditor')),password_hash TEXT NOT NULL,active INTEGER NOT NULL DEFAULT 1,created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS people(id INTEGER PRIMARY KEY,employee_id TEXT UNIQUE NOT NULL,name TEXT NOT NULL,email TEXT UNIQUE,role_title TEXT,department TEXT,manager_id INTEGER,status TEXT NOT NULL DEFAULT 'active',join_date TEXT,classification TEXT NOT NULL DEFAULT 'confidential',created_at TEXT NOT NULL,updated_at TEXT NOT NULL,FOREIGN KEY(manager_id) REFERENCES people(id));
CREATE TABLE IF NOT EXISTS partners(id INTEGER PRIMARY KEY,name TEXT NOT NULL,email TEXT,territory TEXT,agreement_id TEXT,status TEXT NOT NULL DEFAULT 'active',commission_rule TEXT,renewal_date TEXT,classification TEXT NOT NULL DEFAULT 'confidential',created_at TEXT NOT NULL,updated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS documents(id INTEGER PRIMARY KEY,doc_id TEXT UNIQUE NOT NULL,title TEXT NOT NULL,category TEXT NOT NULL,version TEXT NOT NULL DEFAULT '1.0',owner TEXT,status TEXT NOT NULL DEFAULT 'draft',classification TEXT NOT NULL DEFAULT 'internal',approval_date TEXT,next_review TEXT,file_ref TEXT,created_at TEXT NOT NULL,updated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS incidents(id INTEGER PRIMARY KEY,case_id TEXT UNIQUE NOT NULL,type TEXT NOT NULL,severity TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'open',summary TEXT NOT NULL,owner TEXT,reporter_user_id INTEGER,classification TEXT NOT NULL DEFAULT 'restricted',created_at TEXT NOT NULL,updated_at TEXT NOT NULL,FOREIGN KEY(reporter_user_id) REFERENCES users(id));
CREATE TABLE IF NOT EXISTS reviews(id INTEGER PRIMARY KEY,person_id INTEGER NOT NULL,reviewer_user_id INTEGER NOT NULL,quality INTEGER,compliance INTEGER,crm_accuracy INTEGER,notes TEXT,next_action TEXT,status TEXT NOT NULL DEFAULT 'draft',created_at TEXT NOT NULL,FOREIGN KEY(person_id) REFERENCES people(id),FOREIGN KEY(reviewer_user_id) REFERENCES users(id));
CREATE TABLE IF NOT EXISTS audit_log(id INTEGER PRIMARY KEY,user_id INTEGER,action TEXT NOT NULL,entity_type TEXT,entity_id TEXT,result TEXT NOT NULL,ip_hash TEXT,details TEXT,created_at TEXT NOT NULL,FOREIGN KEY(user_id) REFERENCES users(id));
'''

def now(): return datetime.now(timezone.utc).isoformat()
def db():
    if 'db' not in g:
        DB_PATH.parent.mkdir(parents=True,exist_ok=True); g.db=sqlite3.connect(DB_PATH); g.db.row_factory=sqlite3.Row; g.db.execute('PRAGMA foreign_keys=ON')
    return g.db
@app.teardown_appcontext
def close_db(_=None):
    con=g.pop('db',None)
    if con: con.close()
def init_db():
    DB_PATH.parent.mkdir(parents=True,exist_ok=True)
    con=sqlite3.connect(DB_PATH); con.executescript(SCHEMA)
    email=os.environ.get('MAYA_ADMIN_EMAIL'); password=os.environ.get('MAYA_ADMIN_PASSWORD')
    if email and password:
        con.execute('INSERT OR IGNORE INTO users(email,name,role,password_hash,created_at) VALUES(?,?,?,?,?)',(email.lower(),'Engage Lynk Administrator','ceo',generate_password_hash(password),now()))
    docs=[('EL-POL-001','Rules of Engagement','Policy','1.0','Governance','approved','internal'),('EL-SOP-001','BD Partners Detailed SOP','SOP','1.0','Business Development','approved','internal'),('EL-MAYA-001','Maya v2.0 Architecture','System','2.0','Technology / HR','approved','confidential')]
    for x in docs: con.execute('INSERT OR IGNORE INTO documents(doc_id,title,category,version,owner,status,classification,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)',(*x,now(),now()))
    con.commit(); con.close()
init_db()

ROLE_RANK={'employee':1,'partner':1,'manager':2,'auditor':2,'hr':3,'ceo':4}
def ip_hash(): return hashlib.sha256((request.remote_addr or '').encode()).hexdigest()[:16]
def audit(action,etype=None,eid=None,result='allowed',details=None):
    db().execute('INSERT INTO audit_log(user_id,action,entity_type,entity_id,result,ip_hash,details,created_at) VALUES(?,?,?,?,?,?,?,?)',(session.get('uid'),action,etype,str(eid) if eid else None,result,ip_hash(),json.dumps(details) if details else None,now())); db().commit()
def require_role(min_role='employee'):
    def deco(fn):
        @wraps(fn)
        def wrapper(*a,**kw):
            if not session.get('uid'): return jsonify(error='Authentication required'),401
            if ROLE_RANK.get(session.get('role'),0)<ROLE_RANK[min_role]: audit('access_denied',result='denied',details={'path':request.path}); return jsonify(error='Insufficient permission'),403
            if request.method in {'POST','PUT','PATCH','DELETE'} and not hmac.compare_digest(request.headers.get('X-CSRF-Token',''),session.get('csrf','')): return jsonify(error='Invalid CSRF token'),403
            return fn(*a,**kw)
        return wrapper
    return deco

failed={}
def rate_limited(key,limit=8,window=300):
    current=time.time(); values=[x for x in failed.get(key,[]) if current-x<window]; failed[key]=values
    return len(values)>=limit

@app.after_request
def headers(r):
    r.headers['Content-Security-Policy']="default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors https://engagelynk.com https://www.engagelynk.com"
    r.headers['X-Content-Type-Options']='nosniff'; r.headers['Referrer-Policy']='strict-origin-when-cross-origin'; r.headers['Permissions-Policy']='camera=(), microphone=(), geolocation=()'; r.headers['Cache-Control']='no-store'
    if app.config['SESSION_COOKIE_SECURE']: r.headers['Strict-Transport-Security']='max-age=31536000; includeSubDomains'
    return r

@app.get('/')
def home(): return render_template('index.html')
@app.get('/health')
def health(): return jsonify(status='ok',service='Maya v2.0')
@app.post('/api/auth/login')
def login():
    data=request.get_json(silent=True) or {}; email=str(data.get('email','')).strip().lower(); key=ip_hash()+email
    if rate_limited(key): return jsonify(error='Too many attempts; try later'),429
    user=db().execute('SELECT * FROM users WHERE email=? AND active=1',(email,)).fetchone()
    if not user or not check_password_hash(user['password_hash'],str(data.get('password',''))): failed.setdefault(key,[]).append(time.time()); audit('login',result='denied'); return jsonify(error='Invalid credentials'),401
    session.clear(); session.permanent=True; session.update(uid=user['id'],role=user['role'],name=user['name'],csrf=secrets.token_urlsafe(32)); audit('login')
    return jsonify(name=user['name'],role=user['role'],csrf_token=session['csrf'])
@app.post('/api/auth/logout')
@require_role()
def logout(): audit('logout'); session.clear(); return jsonify(ok=True)
@app.get('/api/me')
@require_role()
def me(): return jsonify(id=session['uid'],name=session['name'],role=session['role'])

@app.get('/api/dashboard')
@require_role()
def dashboard():
    q=lambda s: db().execute(s).fetchone()[0]
    return jsonify(active_lynks=35,people=q("SELECT COUNT(*) FROM people WHERE status='active'"),partners=q("SELECT COUNT(*) FROM partners WHERE status='active'"),open_incidents=q("SELECT COUNT(*) FROM incidents WHERE status!='resolved'"),documents_due=q("SELECT COUNT(*) FROM documents WHERE next_review IS NOT NULL AND next_review<=date('now','+30 day')"))

def rows(sql,args=()): return [dict(x) for x in db().execute(sql,args).fetchall()]
@app.get('/api/documents')
@require_role()
def list_documents(): audit('list','documents'); return jsonify(items=rows('SELECT * FROM documents ORDER BY doc_id'))
@app.post('/api/documents')
@require_role('hr')
def create_document():
    d=request.get_json() or {}; required=['doc_id','title','category']
    if any(not str(d.get(x,'')).strip() for x in required): return jsonify(error='doc_id, title and category are required'),400
    try:
        cur=db().execute('INSERT INTO documents(doc_id,title,category,version,owner,status,classification,next_review,file_ref,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)',(d['doc_id'],d['title'],d['category'],d.get('version','1.0'),d.get('owner'),d.get('status','draft'),d.get('classification','internal'),d.get('next_review'),d.get('file_ref'),now(),now())); db().commit(); audit('create','document',cur.lastrowid); return jsonify(id=cur.lastrowid),201
    except sqlite3.IntegrityError: return jsonify(error='Document ID already exists'),409
@app.get('/api/people')
@require_role('manager')
def list_people(): audit('list','people'); return jsonify(items=rows('SELECT id,employee_id,name,email,role_title,department,manager_id,status,join_date FROM people ORDER BY name'))
@app.post('/api/people')
@require_role('hr')
def create_person():
    d=request.get_json() or {}
    if not d.get('employee_id') or not d.get('name'): return jsonify(error='employee_id and name are required'),400
    try:
        cur=db().execute('INSERT INTO people(employee_id,name,email,role_title,department,manager_id,status,join_date,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)',(d['employee_id'],d['name'],d.get('email'),d.get('role_title'),d.get('department'),d.get('manager_id'),d.get('status','active'),d.get('join_date'),now(),now())); db().commit(); audit('create','person',cur.lastrowid); return jsonify(id=cur.lastrowid),201
    except sqlite3.IntegrityError: return jsonify(error='Employee ID or email already exists'),409
@app.get('/api/partners')
@require_role('manager')
def list_partners(): return jsonify(items=rows('SELECT * FROM partners ORDER BY name'))
@app.post('/api/partners')
@require_role('hr')
def create_partner():
    d=request.get_json() or {}
    if not d.get('name'): return jsonify(error='name is required'),400
    cur=db().execute('INSERT INTO partners(name,email,territory,agreement_id,status,commission_rule,renewal_date,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)',(d['name'],d.get('email'),d.get('territory'),d.get('agreement_id'),d.get('status','active'),d.get('commission_rule'),d.get('renewal_date'),now(),now())); db().commit(); audit('create','partner',cur.lastrowid); return jsonify(id=cur.lastrowid),201
@app.get('/api/incidents')
@require_role('hr')
def list_incidents(): audit('list','incidents'); return jsonify(items=rows('SELECT id,case_id,type,severity,status,summary,owner,created_at,updated_at FROM incidents ORDER BY created_at DESC'))
@app.post('/api/incidents')
@require_role()
def create_incident():
    d=request.get_json() or {}; allowed={'low','medium','high','critical'}
    if not d.get('type') or not d.get('summary') or d.get('severity') not in allowed: return jsonify(error='type, summary and valid severity are required'),400
    case='EL-INC-'+datetime.now(timezone.utc).strftime('%Y%m%d')+'-'+secrets.token_hex(3).upper()
    cur=db().execute('INSERT INTO incidents(case_id,type,severity,summary,owner,reporter_user_id,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)',(case,d['type'],d['severity'],d['summary'][:2000],d.get('owner'),session['uid'],now(),now())); db().commit(); audit('create','incident',cur.lastrowid); return jsonify(id=cur.lastrowid,case_id=case),201
@app.get('/api/audit')
@require_role('auditor')
def audit_view(): return jsonify(items=rows('SELECT id,user_id,action,entity_type,entity_id,result,details,created_at FROM audit_log ORDER BY id DESC LIMIT 500'))

@app.post('/api/chat')
@require_role()
def chat():
    text=str((request.get_json(silent=True) or {}).get('message','')).strip()[:1000]; q=text.lower()
    blocked=['password','otp','bank account','aadhaar','api key']
    if any(x in q for x in blocked): response='Please do not enter passwords, authentication codes, banking details, government identifiers, or API keys. Use the approved secure channel.'; escalated=True
    elif any(x in q for x in ['harass','threat','assault','unsafe']): response='Thank you for raising this. Is anyone in immediate danger? If yes, contact emergency support first. I can route the matter to the authorised complaint or incident owner without deciding the facts in chat.'; escalated=True
    elif 'leave' in q: response='I can guide the documented leave workflow. Please provide the leave type and dates without sensitive medical details. Approval remains with the authorised manager or HR owner.'; escalated=False
    elif any(x in q for x in ['resign','offboard','exit']): response='I can prepare the offboarding checklist: handover, records transfer, assets, access revocation, shared credential rotation, and confidentiality confirmation. An authorised person must approve the final action.'; escalated=False
    else: response='Certainly. I can assist with governance documents, onboarding, performance, partners, incidents, privacy, and policy routing. Please state the desired outcome and I will identify the next controlled step.'; escalated=False
    audit('chat','assistant',result='escalated' if escalated else 'allowed',details={'length':len(text)})
    return jsonify(response=response,escalated=escalated)

if __name__=='__main__': app.run(host='0.0.0.0',port=int(os.environ.get('PORT','8080')),debug=False)
