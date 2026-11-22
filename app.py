import os, json, hmac, hashlib, base64, uuid, calendar
from datetime import datetime, date
from decimal import Decimal, ROUND_HALF_UP
from functools import wraps
from pathlib import Path
from urllib.parse import urlparse
import requests
from flask import Flask, render_template, request, redirect, url_for, flash, session, abort, send_file, jsonify
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import UniqueConstraint
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
load_dotenv()
app=Flask(__name__)
app.secret_key=os.getenv('SECRET_KEY','dev-only-change-me')
app.config.update(SESSION_COOKIE_HTTPONLY=True,SESSION_COOKIE_SAMESITE='Lax',SESSION_COOKIE_SECURE=os.getenv('PUBLIC_BASE_URL','').startswith('https://'),MAX_CONTENT_LENGTH=int(os.getenv('MAX_UPLOAD_MB','8'))*1024*1024)
dburl=os.getenv('DATABASE_URL','sqlite:///local.db')
if dburl.startswith('postgres://'): dburl=dburl.replace('postgres://','postgresql+psycopg://',1)
if dburl.startswith('postgresql://'): dburl=dburl.replace('postgresql://','postgresql+psycopg://',1)
app.config['SQLALCHEMY_DATABASE_URI']=dburl
app.config['SQLALCHEMY_TRACK_MODIFICATIONS']=False
db=SQLAlchemy(app)
LIVE=False  # Sandbox-only release: no live disbursement or real lending activation
UPLOAD=Path(os.getenv('UPLOAD_DIR',str(Path(__file__).parent/'uploads')))
UPLOAD.mkdir(parents=True,exist_ok=True)
class User(db.Model):
 id=db.Column(db.Integer,primary_key=True); name=db.Column(db.String(150),nullable=False); email=db.Column(db.String(200),unique=True,nullable=False); password=db.Column(db.String(255),nullable=False); role=db.Column(db.String(20),default='customer'); phone=db.Column(db.String(20)); created=db.Column(db.DateTime,default=datetime.utcnow)
class Application(db.Model):
 id=db.Column(db.Integer,primary_key=True); user_id=db.Column(db.Integer,db.ForeignKey('user.id'),nullable=False); amount=db.Column(db.Numeric(14,2),nullable=False); purpose=db.Column(db.String(500),nullable=False); dob=db.Column(db.String(20)); address=db.Column(db.Text); pan_last4=db.Column(db.String(4)); aadhaar_last4=db.Column(db.String(4)); bank_last4=db.Column(db.String(4)); bank_name=db.Column(db.String(120)); ifsc=db.Column(db.String(20)); employment=db.Column(db.String(100)); monthly_income=db.Column(db.Numeric(14,2)); status=db.Column(db.String(30),default='submitted'); kyc_status=db.Column(db.String(30),default='pending'); admin_note=db.Column(db.Text); created=db.Column(db.DateTime,default=datetime.utcnow); user=db.relationship('User')
class Document(db.Model):
 id=db.Column(db.Integer,primary_key=True); application_id=db.Column(db.Integer,db.ForeignKey('application.id'),nullable=False); kind=db.Column(db.String(30),nullable=False); filename=db.Column(db.String(300),nullable=False); original_name=db.Column(db.String(200)); created=db.Column(db.DateTime,default=datetime.utcnow)
class Loan(db.Model):
 id=db.Column(db.Integer,primary_key=True); application_id=db.Column(db.Integer,db.ForeignKey('application.id'),unique=True,nullable=False); principal=db.Column(db.Numeric(14,2),nullable=False); annual_or_monthly=db.Column(db.String(10),nullable=False); rate=db.Column(db.Numeric(8,3),nullable=False); method=db.Column(db.String(12),nullable=False); tenure=db.Column(db.Integer,nullable=False); emi=db.Column(db.Numeric(14,2),nullable=False); total=db.Column(db.Numeric(14,2),nullable=False); status=db.Column(db.String(25),default='offered'); accepted_at=db.Column(db.DateTime); disbursed_at=db.Column(db.DateTime); created=db.Column(db.DateTime,default=datetime.utcnow); application=db.relationship('Application')
class Installment(db.Model):
 id=db.Column(db.Integer,primary_key=True); loan_id=db.Column(db.Integer,db.ForeignKey('loan.id'),nullable=False); number=db.Column(db.Integer,nullable=False); due_date=db.Column(db.Date,nullable=False); amount=db.Column(db.Numeric(14,2),nullable=False); paid=db.Column(db.Numeric(14,2),default=0); __table_args__=(UniqueConstraint('loan_id','number'),)
class Payment(db.Model):
 id=db.Column(db.Integer,primary_key=True); installment_id=db.Column(db.Integer,db.ForeignKey('installment.id'),nullable=False); order_id=db.Column(db.String(100),unique=True,nullable=False); amount=db.Column(db.Numeric(14,2),nullable=False); status=db.Column(db.String(25),default='pending'); cf_payment_id=db.Column(db.String(100)); created=db.Column(db.DateTime,default=datetime.utcnow)
class Audit(db.Model):
 id=db.Column(db.Integer,primary_key=True); actor_id=db.Column(db.Integer); action=db.Column(db.String(100)); subject=db.Column(db.String(100)); detail=db.Column(db.Text); created=db.Column(db.DateTime,default=datetime.utcnow)
def money(v): return Decimal(str(v)).quantize(Decimal('.01'),rounding=ROUND_HALF_UP)
def audit(action,subject,detail=''):
 db.session.add(Audit(actor_id=session.get('uid'),action=action,subject=subject,detail=detail))
def user(): return db.session.get(User,session['uid']) if session.get('uid') else None
@app.context_processor
def context(): return dict(me=user(),live=LIVE)
def login_required(role=None):
 def outer(fn):
  @wraps(fn)
  def inner(*a,**kw):
   u=user()
   if not u: return redirect(url_for('login'))
   if role and u.role!=role: abort(403)
   return fn(*a,**kw)
  return inner
 return outer
@app.before_request
def csrf_check():
 if request.method in ('POST','PUT','PATCH','DELETE') and request.endpoint!='cashfree_webhook':
  if not hmac.compare_digest(str(session.get('csrf','')),str(request.form.get('csrf',request.headers.get('X-CSRF-Token','')))) or not session.get('csrf'): abort(400,'Invalid CSRF token')
@app.context_processor
def csrf():
 if 'csrf' not in session: session['csrf']=uuid.uuid4().hex
 return {'csrf':session['csrf']}
@app.route('/')
def home(): return redirect(url_for('dashboard') if user() else url_for('login'))
@app.route('/register',methods=['GET','POST'])
def register():
 if request.method=='POST':
  email=request.form['email'].strip().lower(); pw=request.form['password']
  if len(pw)<10: flash('Use a password of at least 10 characters.'); return redirect(url_for('register'))
  if User.query.filter_by(email=email).first(): flash('Email already registered.'); return redirect(url_for('register'))
  u=User(name=request.form['name'].strip(),email=email,phone=request.form['phone'].strip(),password=generate_password_hash(pw)); db.session.add(u); db.session.commit(); session.clear(); session['uid']=u.id; return redirect(url_for('dashboard'))
 return render_template('auth.html',register=True)
@app.route('/login',methods=['GET','POST'])
def login():
 if request.method=='POST':
  u=User.query.filter_by(email=request.form['email'].strip().lower()).first()
  if u and check_password_hash(u.password,request.form['password']): session.clear(); session['uid']=u.id; return redirect(url_for('dashboard'))
  flash('Invalid login details.')
 return render_template('auth.html',register=False)
@app.post('/logout')
def logout(): session.clear(); return redirect(url_for('login'))
@app.route('/dashboard')
@login_required()
def dashboard():
 u=user()
 if u.role=='admin':
  return render_template('admin.html',applications=Application.query.order_by(Application.created.desc()).all(),loans=Loan.query.order_by(Loan.created.desc()).all(),auditlogs=Audit.query.order_by(Audit.created.desc()).limit(15).all())
 apps=Application.query.filter_by(user_id=u.id).order_by(Application.created.desc()).all()
 loans=Loan.query.join(Application).filter(Application.user_id==u.id).all()
 return render_template('dashboard.html',applications=apps,loans=loans)
@app.route('/apply',methods=['GET','POST'])
@login_required('customer')
def apply():
 if request.method=='POST':
  try:
   amount=money(request.form['amount']); income=money(request.form['income'])
   if amount<=0 or income<0: raise ValueError()
  except Exception: flash('Enter valid amounts.'); return redirect(url_for('apply'))
  a=Application(user_id=user().id,amount=amount,purpose=request.form['purpose'][:500],dob=request.form['dob'],address=request.form['address'],pan_last4=request.form['pan_last4'][-4:],aadhaar_last4=request.form['aadhaar_last4'][-4:],bank_last4=request.form['bank_last4'][-4:],bank_name=request.form['bank_name'],ifsc=request.form['ifsc'],employment=request.form['employment'],monthly_income=income)
  db.session.add(a); db.session.flush()
  kinds=['photo','pan','aadhaar','bank_proof','income_proof']
  for kind in kinds:
   f=request.files.get(kind)
   if not f or not f.filename: db.session.rollback(); flash('All five document uploads are required.'); return redirect(url_for('apply'))
   ext=Path(secure_filename(f.filename)).suffix.lower()
   if ext not in ('.pdf','.png','.jpg','.jpeg','.webp'): db.session.rollback(); flash('Only PDF and image files are allowed.'); return redirect(url_for('apply'))
   head=f.stream.read(16); f.stream.seek(0)
   valid=(ext=='.pdf' and head.startswith(b'%PDF-')) or (ext=='.png' and head.startswith(b'\x89PNG\r\n\x1a\n')) or (ext in ('.jpg','.jpeg') and head.startswith(b'\xff\xd8\xff')) or (ext=='.webp' and head[:4]==b'RIFF' and head[8:12]==b'WEBP')
   if not valid: db.session.rollback(); flash('Document contents do not match the selected file type.'); return redirect(url_for('apply'))
   name=f'{uuid.uuid4().hex}{ext}'; f.save(UPLOAD/name); db.session.add(Document(application_id=a.id,kind=kind,filename=name,original_name=secure_filename(f.filename)))
  audit('application_submitted',f'application:{a.id}'); db.session.commit(); flash('Application submitted for manual verification.'); return redirect(url_for('dashboard'))
 return render_template('apply.html')
@app.route('/admin/application/<int:aid>')
@login_required('admin')
def review(aid):
 a=db.get_or_404(Application,aid); loan=Loan.query.filter_by(application_id=aid).first(); docs=Document.query.filter_by(application_id=aid).all(); return render_template('review.html',a=a,docs=docs,loan=loan)
@app.route('/document/<int:did>')
@login_required()
def document(did):
 d=db.get_or_404(Document,did); a=db.get_or_404(Application,d.application_id)
 if user().role!='admin' and a.user_id!=user().id: abort(403)
 return send_file(UPLOAD/Path(d.filename).name,as_attachment=True,download_name=d.original_name)
@app.post('/admin/application/<int:aid>/kyc')
@login_required('admin')
def kyc(aid):
 a=db.get_or_404(Application,aid); status=request.form['status']
 if status not in ('verified','rejected','correction_requested'): abort(400)
 a.kyc_status=status; a.admin_note=request.form.get('note','')[:2000]
 if status=='rejected': a.status='rejected'
 audit('kyc_'+status,f'application:{aid}',a.admin_note); db.session.commit(); return redirect(url_for('review',aid=aid))
def calc(principal,rate,rate_type,method,tenure):
 r=Decimal(str(rate))/(Decimal('100') if rate_type=='monthly' else Decimal('1200')); p=money(principal)
 if method=='flat': total=money(p*(1+r*tenure)); emi=money(total/tenure)
 else:
  emi=money(p/tenure if r==0 else p*r*(1+r)**tenure/((1+r)**tenure-1)); total=money(emi*tenure)
 return emi,total
@app.post('/admin/application/<int:aid>/offer')
@login_required('admin')
def offer(aid):
 a=db.get_or_404(Application,aid)
 if a.kyc_status!='verified' or Loan.query.filter_by(application_id=aid).first(): abort(400,'KYC must be verified; only one offer per application.')
 try:
  p=money(request.form['principal']); rate=Decimal(request.form['rate']); tenure=int(request.form['tenure']); rt=request.form['rate_type']; method=request.form['method']
  if not (p.is_finite() and rate.is_finite() and p>0 and Decimal(0)<=rate<=Decimal(60) and 1<=tenure<=120 and rt in ('monthly','annual') and method in ('flat','reducing')): raise ValueError()
  emi,total=calc(p,rate,rt,method,tenure)
 except Exception: abort(400,'Invalid loan terms')
 loan=Loan(application_id=aid,principal=p,rate=rate,annual_or_monthly=rt,method=method,tenure=tenure,emi=emi,total=total)
 db.session.add(loan); a.status='offered'; audit('loan_offered',f'application:{aid}',f'principal={p},rate={rate},type={rt},method={method},tenure={tenure}'); db.session.commit(); return redirect(url_for('review',aid=aid))
@app.post('/loan/<int:lid>/accept')
@login_required('customer')
def accept(lid):
 l=db.get_or_404(Loan,lid)
 if l.application.user_id!=user().id or l.status!='offered': abort(403)
 l.status='accepted'; l.accepted_at=datetime.utcnow(); l.application.status='accepted'; audit('offer_accepted',f'loan:{lid}'); db.session.commit(); return redirect(url_for('loan_detail',lid=lid))
def add_months(d,n):
 m=d.month-1+n; y=d.year+m//12; month=m%12+1; return date(y,month,min(d.day,calendar.monthrange(y,month)[1]))
@app.post('/admin/loan/<int:lid>/disburse')
@login_required('admin')
def disburse(lid):
 if not LIVE: abort(403,'Live lending disabled. Verify licensing and explicitly enable after compliance review.')
 l=db.get_or_404(Loan,lid)
 if l.status!='accepted': abort(400)
 l.status='active'; l.disbursed_at=datetime.utcnow(); l.application.status='active'; start=date.today(); assigned=Decimal('0')
 for n in range(1,l.tenure+1):
  amt=l.emi if n<l.tenure else money(l.total-assigned); assigned+=amt
  db.session.add(Installment(loan_id=l.id,number=n,due_date=add_months(start,n),amount=amt))
 audit('loan_disbursed_recorded',f'loan:{lid}','Admin confirmed external disbursement'); db.session.commit(); return redirect(url_for('review',aid=l.application_id))
@app.route('/loan/<int:lid>')
@login_required()
def loan_detail(lid):
 l=db.get_or_404(Loan,lid)
 if user().role!='admin' and l.application.user_id!=user().id: abort(403)
 installments=Installment.query.filter_by(loan_id=lid).order_by(Installment.number).all()
 return render_template('loan.html',loan=l,installments=installments)
def cashfree_base(): return 'https://sandbox.cashfree.com/pg' if os.getenv('CASHFREE_ENV','sandbox')=='sandbox' else 'https://api.cashfree.com/pg'
def cashfree_headers(): return {'x-client-id':os.getenv('CASHFREE_APP_ID',''),'x-client-secret':os.getenv('CASHFREE_SECRET_KEY',''),'x-api-version':os.getenv('CASHFREE_API_VERSION','2025-01-01'),'Content-Type':'application/json'}
@app.post('/installment/<int:iid>/pay')
@login_required('customer')
def pay(iid):
 ins=db.get_or_404(Installment,iid); l=db.get_or_404(Loan,ins.loan_id)
 if l.application.user_id!=user().id or l.status!='active': abort(403)
 remaining=money(ins.amount-ins.paid)
 if remaining<=0: abort(400)
 if not os.getenv('CASHFREE_APP_ID') or not os.getenv('CASHFREE_SECRET_KEY'): flash('Cashfree has not been configured.'); return redirect(url_for('loan_detail',lid=l.id))
 oid='OWL'+uuid.uuid4().hex[:24]; payload={'order_id':oid,'order_amount':float(remaining),'order_currency':'INR','customer_details':{'customer_id':str(user().id),'customer_name':user().name,'customer_email':user().email,'customer_phone':user().phone or '9999999999'},'order_meta':{'return_url':os.getenv('PUBLIC_BASE_URL','').rstrip('/')+url_for('payment_return',oid=oid),'notify_url':os.getenv('PUBLIC_BASE_URL','').rstrip('/')+url_for('cashfree_webhook')}}
 try:
  res=requests.post(cashfree_base()+'/orders',headers=cashfree_headers(),json=payload,timeout=15); res.raise_for_status(); data=res.json(); ps=data['payment_session_id']
 except Exception: flash('Unable to initiate Cashfree payment. Check gateway settings.'); return redirect(url_for('loan_detail',lid=l.id))
 db.session.add(Payment(installment_id=iid,order_id=oid,amount=remaining)); db.session.commit(); return render_template('checkout.html',payment_session_id=ps,env=os.getenv('CASHFREE_ENV','sandbox'))
@app.route('/payment/return/<oid>')
@login_required()
def payment_return(oid):
 p=Payment.query.filter_by(order_id=oid).first_or_404(); ins=db.get_or_404(Installment,p.installment_id); l=db.get_or_404(Loan,ins.loan_id)
 if user().role!='admin' and l.application.user_id!=user().id: abort(403)
 flash('Payment initiated. Final status is confirmed only after verified gateway notification.'); return redirect(url_for('loan_detail',lid=l.id))
@app.post('/webhooks/cashfree')
def cashfree_webhook():
 raw=request.get_data(); timestamp=request.headers.get('x-webhook-timestamp',''); signature=request.headers.get('x-webhook-signature',''); secret=os.getenv('CASHFREE_SECRET_KEY','')
 if not secret or not timestamp or not signature: abort(401)
 digest=base64.b64encode(hmac.new(secret.encode(),timestamp.encode()+raw,hashlib.sha256).digest()).decode()
 if not hmac.compare_digest(digest,signature): abort(401)
 try: data=json.loads(raw); payment=data['data']['payment']; order=data['data']['order']; oid=order['order_id']
 except Exception: abort(400)
 p=Payment.query.filter_by(order_id=oid).first()
 if not p: return '',200
 if p.status=='success': return '',200
 if payment.get('payment_status')!='SUCCESS': return '',200
 if money(order.get('order_amount',0))!=money(p.amount) or order.get('order_currency','INR')!='INR': abort(400)
 ins=db.get_or_404(Installment,p.installment_id)
 if money(ins.paid+p.amount)>money(ins.amount):
  audit('payment_overage_requires_review',f'payment:{p.id}',oid); p.status='review'; db.session.commit(); return '',200
 p.status='success'; p.cf_payment_id=str(payment.get('cf_payment_id','')); ins=db.get_or_404(Installment,p.installment_id); ins.paid=money(ins.paid+p.amount)
 loan=db.get_or_404(Loan,ins.loan_id)
 if all(money(i.paid)>=money(i.amount) for i in Installment.query.filter_by(loan_id=loan.id).all()): loan.status='closed'; loan.application.status='closed'
 audit('payment_verified',f'payment:{p.id}',oid); db.session.commit(); return '',200
@app.get('/health')
def health(): return jsonify(status='ok')

@app.get('/admin/customers')
@login_required('admin')
def admin_customers():
 customers=User.query.filter_by(role='customer').order_by(User.created.desc()).all()
 return render_template('customers.html',customers=customers)

@app.get('/admin/payments')
@login_required('admin')
def admin_payments():
 payments=Payment.query.order_by(Payment.created.desc()).limit(250).all()
 return render_template('payments.html',payments=payments)

@app.get('/admin/report')
@login_required('admin')
def admin_report():
 from sqlalchemy import func
 apps=Application.query.count(); customers=User.query.filter_by(role='customer').count()
 loan_count=Loan.query.count()
 principal=db.session.query(func.coalesce(func.sum(Loan.principal),0)).scalar()
 pending=Application.query.filter_by(kyc_status='pending').count()
 successful=Payment.query.filter_by(status='success').count()
 return render_template('report.html',apps=apps,customers=customers,loan_count=loan_count,principal=principal,pending=pending,successful=successful)

@app.get('/admin/report.csv')
@login_required('admin')
def admin_report_csv():
 import csv, io
 from flask import Response
 stream=io.StringIO(); writer=csv.writer(stream)
 writer.writerow(['loan_id','application_id','principal_inr','rate_percent','rate_period','method','tenure_months','status','total_repayment_inr'])
 for l in Loan.query.order_by(Loan.id).all():
  writer.writerow([l.id,l.application_id,str(l.principal),str(l.rate),l.annual_or_monthly,l.method,l.tenure,l.status,str(l.total)])
 audit('admin_export_loans','report:csv'); db.session.commit()
 return Response(stream.getvalue(),mimetype='text/csv',headers={'Content-Disposition':'attachment; filename=owl-finance-loans.csv','Cache-Control':'no-store'})

def initialize_database_and_admin():
    # Runs on Gunicorn startup as well as local startup.
    with app.app_context():
        db.create_all()
        email = os.getenv('ADMIN_EMAIL', '').strip().lower()
        password = os.getenv('ADMIN_PASSWORD', '')

        if not email or not password:
            app.logger.warning('Admin bootstrap skipped: ADMIN_EMAIL or ADMIN_PASSWORD is missing.')
            return
        if len(password) < 12:
            app.logger.error('Admin bootstrap skipped: ADMIN_PASSWORD must contain at least 12 characters. Change it in Render Environment and redeploy.')
            return

        existing = User.query.filter_by(email=email).first()
        if existing:
            if existing.role != 'admin':
                app.logger.error('Admin bootstrap blocked: ADMIN_EMAIL belongs to an existing non-admin user. No role was changed.')
            else:
                app.logger.info('Admin account already exists; password was not changed.')
            return

        try:
            db.session.add(User(
                name='OWL FINANCE Admin',
                email=email,
                password=generate_password_hash(password),
                role='admin'
            ))
            db.session.commit()
            app.logger.info('Initial OWL FINANCE administrator created successfully.')
        except Exception:
            db.session.rollback()
            # Two Gunicorn workers may try to create the same account simultaneously.
            if User.query.filter_by(email=email, role='admin').first():
                app.logger.info('Administrator was initialized by another worker.')
            else:
                app.logger.exception('Admin bootstrap failed.')
                raise

initialize_database_and_admin()

if __name__ == '__main__':
    app.run(debug=os.getenv('FLASK_DEBUG') == '1')
