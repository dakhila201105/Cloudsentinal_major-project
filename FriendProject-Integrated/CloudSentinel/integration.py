import json, secrets
from datetime import datetime, timedelta
from functools import wraps
import os, urllib.request, json, secrets
from flask import Blueprint, request, jsonify, render_template, abort
from extensions import db
from models import User, AuditLog, ThreatLog
from integration_models import SecurityIdentity, SecurityEvent, SecuritySession, IntegrationAccessRequest
from security.risk_engine import compute_risk
from security.zero_trust import simulate_geo_lookup

bp = Blueprint('integration', __name__)
SESSION_PRESENCE_WINDOW = timedelta(seconds=120)

def _active_session_count(user_id=None):
    cutoff=datetime.utcnow()-SESSION_PRESENCE_WINDOW
    query=SecuritySession.query.filter(SecuritySession.status=='ACTIVE',SecuritySession.last_activity>=cutoff)
    if user_id is not None: query=query.filter_by(bookstream_user_id=str(user_id))
    return query.count()


def _bookstream_request(path, method='GET', payload=None):
    base=os.environ.get('BOOKSTREAM_BACKEND_URL','http://127.0.0.1:5000')
    req=urllib.request.Request(base+path, method=method, headers={'Content-Type':'application/json','X-CloudSentinel-Service-Key':os.environ.get('CLOUDSENTINEL_SERVICE_KEY','dev-integration-key')})
    if payload is not None: req.data=json.dumps(payload).encode()
    with urllib.request.urlopen(req, timeout=6) as resp: return json.loads(resp.read().decode())

def _service_ok():
    from flask import current_app
    expected = current_app.config.get('CLOUDSENTINEL_SERVICE_KEY', 'dev-integration-key')
    supplied = request.headers.get('X-CloudSentinel-Service-Key', '')
    return secrets.compare_digest(supplied, expected)

def service_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not _service_ok():
            return jsonify({'message':'Unauthorized service request'}), 401
        return fn(*args, **kwargs)
    return wrapper

def _risk_for(user_id, ip, fingerprint, user_agent):
    now = datetime.utcnow()
    recent_failed = SecurityEvent.query.filter_by(bookstream_user_id=str(user_id), event_type='LOGIN_FAILED').filter(SecurityEvent.timestamp >= now-timedelta(minutes=15)).count()
    known_device = SecurityEvent.query.filter_by(bookstream_user_id=str(user_id), device_fingerprint=fingerprint).first() is not None
    location = simulate_geo_lookup(ip)
    known_location = SecurityEvent.query.filter_by(bookstream_user_id=str(user_id), location=location).first() is not None
    reqs = SecurityEvent.query.filter_by(bookstream_user_id=str(user_id)).filter(SecurityEvent.timestamp >= now-timedelta(minutes=1)).count()
    from flask import current_app
    score, level, reasons, anomaly = compute_risk(current_app.config, now.hour, known_device, known_location, recent_failed, reqs)
    if score >= 80:
        level = 'CRITICAL'
    elif score > 60:
        level = 'HIGH'
    return score, level, reasons, anomaly, location

def _event(user_id, event_type, **kw):
    ev = SecurityEvent(event_id=secrets.token_hex(12), bookstream_user_id=str(user_id), event_type=event_type, **kw)
    db.session.add(ev)
    return ev

def _event_metadata(event):
    try:
        return json.loads(event.metadata_json or '{}')
    except (TypeError, ValueError):
        return {}

def _audit(username, action, user_id, ip, device, risk, status):
    db.session.add(AuditLog(username=username, device_id=device or '-', browser='', ip_address=ip or '-', country=simulate_geo_lookup(ip or '127.0.0.1'), auth_status=status, risk_score=risk, admin_decision='N/A'))

@bp.post('/api/integration/users')
@service_required
def upsert_user():
    data = request.get_json(force=True) or {}
    bid = str(data.get('bookstream_user_id',''))
    if not bid: return jsonify({'message':'bookstream_user_id required'}),400
    identity = SecurityIdentity.query.filter_by(bookstream_user_id=bid).first()
    if not identity:
        identity = SecurityIdentity(bookstream_user_id=bid)
        db.session.add(identity)
    for k in ('username','email','role'):
        if k in data: setattr(identity,k,data[k])
    if data.get('status') in ('ACTIVE','FROZEN','BLOCKED'): identity.status=data['status']
    identity.last_seen=datetime.utcnow()
    db.session.commit()
    return jsonify({'id':identity.id,'bookstream_user_id':bid,'status':identity.status})

@bp.post('/api/integration/login-evaluate')
@service_required
def login_evaluate():
    data=request.get_json(force=True) or {}
    bid=str(data.get('bookstream_user_id',''))
    identity=SecurityIdentity.query.filter_by(bookstream_user_id=bid).first()
    if not identity: return jsonify({'decision':'BLOCK','message':'Security identity not registered'}),403
    ip=data.get('ip_address') or '0.0.0.0'; fp=data.get('device_fingerprint') or '' ; ua=data.get('user_agent','')
    score,level,reasons,anomaly,location=_risk_for(bid,ip,fp,ua)
    if identity.status != 'ACTIVE':
        previous=SecurityEvent.query.filter_by(bookstream_user_id=bid,event_type='FROZEN_LOGIN_ATTEMPT').order_by(SecurityEvent.timestamp.desc()).first()
        baseline=previous.risk_score if previous else max(score,1)
        escalated=min(float(baseline)*5,100.0)
        if escalated>=80: escalated_level='CRITICAL'
        elif escalated>60: escalated_level='HIGH'
        elif escalated>30: escalated_level='MEDIUM'
        else: escalated_level='LOW'
        attempts=SecurityEvent.query.filter_by(bookstream_user_id=bid,event_type='FROZEN_LOGIN_ATTEMPT').count()+1
        rid='AR-'+secrets.token_hex(8)
        reason=f"{identity.status} account sign-in attempt #{attempts}; risk multiplied 5x to {escalated:g}/100. " + ('; '.join(reasons) or 'Credentials verified against BookStream')
        db.session.add(IntegrationAccessRequest(request_id=rid,bookstream_user_id=bid,username=identity.username,email=identity.email,ip_address=ip,device_fingerprint=fp,user_agent=ua,location=location,risk_score=escalated,anomaly_score=anomaly,risk_level=escalated_level,reasons=reason,request_type='FROZEN_ACCOUNT_LOGIN'))
        _event(bid,'FROZEN_LOGIN_ATTEMPT',ip_address=ip,device_fingerprint=fp,user_agent=ua,location=location,risk_score=escalated,anomaly_score=anomaly,risk_level=escalated_level,action='PENDING_ADMIN_REVIEW',reason=reason)
        identity.last_seen=datetime.utcnow(); db.session.commit()
        return jsonify({'decision':'PENDING','request_id':rid,'risk_score':escalated,'risk_level':escalated_level,'anomaly_score':anomaly,'reasons':[reason],'message':'Account sign-in request sent for administrator review'}),202
    if level in ('HIGH','CRITICAL'):
        _event(bid,'LOGIN',ip_address=ip,device_fingerprint=fp,user_agent=ua,location=location,risk_score=score,anomaly_score=anomaly,risk_level=level,action='BLOCKED',reason='; '.join(reasons))
        db.session.add(ThreatLog(source_ip=ip,description=f'{level} login risk for {identity.username}',severity=level))
        db.session.commit()
        return jsonify({'decision':'BLOCK','risk_score':score,'risk_level':level,'anomaly_score':anomaly,'reasons':reasons}),403
    if level=='MEDIUM':
        rid='AR-'+secrets.token_hex(8)
        ar=IntegrationAccessRequest(request_id=rid,bookstream_user_id=bid,username=identity.username,email=identity.email,ip_address=ip,device_fingerprint=fp,user_agent=ua,location=location,risk_score=score,anomaly_score=anomaly,risk_level=level,reasons='; '.join(reasons))
        db.session.add(ar)
        _event(bid,'LOGIN',ip_address=ip,device_fingerprint=fp,user_agent=ua,location=location,risk_score=score,anomaly_score=anomaly,risk_level=level,action='PENDING_APPROVAL',reason='; '.join(reasons))
        db.session.commit()
        return jsonify({'decision':'PENDING','request_id':rid,'risk_score':score,'risk_level':level,'anomaly_score':anomaly,'reasons':reasons}),202
    sid='CS-'+secrets.token_hex(24)
    ss=SecuritySession(session_id=sid,bookstream_user_id=bid,ip_address=ip,device_fingerprint=fp,user_agent=ua,location=location,risk_score=score,risk_level=level)
    db.session.add(ss)
    _event(bid,'LOGIN',ip_address=ip,device_fingerprint=fp,user_agent=ua,location=location,session_id=sid,risk_score=score,anomaly_score=anomaly,risk_level=level,action='ALLOWED',reason='; '.join(reasons) or 'Normal behavior')
    _audit(identity.username,'LOGIN',bid,ip,fp,score,'ALLOWED')
    db.session.commit()
    return jsonify({'decision':'ALLOW','security_session_id':sid,'risk_score':score,'risk_level':level,'anomaly_score':anomaly,'reasons':reasons})

@bp.post('/api/integration/events')
@service_required
def events():
    data=request.get_json(force=True) or {}
    bid=str(data.get('bookstream_user_id',''))
    if not bid: return jsonify({'message':'bookstream_user_id required'}),400
    identity=SecurityIdentity.query.filter_by(bookstream_user_id=bid).first()
    if not identity: return jsonify({'message':'Security identity not found'}),404
    event_type=str(data.get('event_type','API_REQUEST'))[:50]
    ip=data.get('ip_address') or '0.0.0.0'; fp=data.get('device_fingerprint',''); ua=data.get('user_agent',''); location=data.get('location') or simulate_geo_lookup(ip)
    score,level,reasons,anomaly,location=_risk_for(bid,ip,fp,ua)
    ev=_event(bid,event_type,ip_address=ip,device_fingerprint=fp,user_agent=ua,location=location,session_id=data.get('session_id'),resource_id=data.get('resource_id'),resource_name=data.get('resource_name'),risk_score=score,anomaly_score=anomaly,risk_level=level,action='RECORDED',reason='; '.join(reasons),metadata_json=json.dumps(data.get('metadata',{})))
    if data.get('session_id'):
        active_session=SecuritySession.query.filter_by(session_id=data.get('session_id'),status='ACTIVE').first()
        if active_session: active_session.last_activity=datetime.utcnow()
    identity.last_seen=datetime.utcnow()
    if level in ('HIGH','CRITICAL') and event_type not in ('LOGIN_FAILED',):
        ev.action='RESTRICTED'; db.session.add(ThreatLog(source_ip=ip,description=f'{event_type} elevated risk for {identity.username}',severity=level))
    db.session.commit()
    return jsonify({'event_id':ev.event_id,'risk_score':score,'risk_level':level,'anomaly_score':anomaly,'reasons':reasons})

@bp.post('/api/integration/access-request/<request_id>/status')
@service_required
def access_status(request_id):
    ar=IntegrationAccessRequest.query.filter_by(request_id=request_id).first_or_404()
    if ar.status=='APPROVED':
        if not ar.security_session_id:
            sid='CS-'+secrets.token_hex(24)
            ss=SecuritySession(session_id=sid,bookstream_user_id=ar.bookstream_user_id,ip_address=ar.ip_address,device_fingerprint=ar.device_fingerprint,user_agent=ar.user_agent,location=ar.location,risk_score=ar.risk_score,risk_level=ar.risk_level)
            db.session.add(ss); ar.security_session_id=sid; ar.decided_at=ar.decided_at or datetime.utcnow()
            _event(ar.bookstream_user_id,'ADMIN_APPROVAL',ip_address=ar.ip_address,device_fingerprint=ar.device_fingerprint,location=ar.location,session_id=sid,risk_score=ar.risk_score,anomaly_score=ar.anomaly_score,risk_level=ar.risk_level,action='APPROVED',reason='Administrator approved access')
            db.session.commit()
        return jsonify({'status':'APPROVED','security_session_id':ar.security_session_id,'bookstream_user_id':ar.bookstream_user_id})
    if ar.status=='DENIED' and ar.request_type=='FROZEN_ACCOUNT_LOGIN':
        return jsonify({'status':'DENIED','risk_score':ar.risk_score,'risk_level':ar.risk_level,'message':'Your BookStream account remains frozen and blocked. Please contact the BookStream administrator if you believe this is a mistake. An administrator reviewed this sign-in attempt and chose to keep the account frozen.'})
    return jsonify({'status':ar.status,'risk_score':ar.risk_score,'risk_level':ar.risk_level})

@bp.post('/api/integration/session/validate')
@service_required
def validate_session():
    data=request.get_json(force=True) or {}; ss=SecuritySession.query.filter_by(session_id=data.get('security_session_id')).first()
    if not ss or ss.status!='ACTIVE': return jsonify({'valid':False}),401
    ss.last_activity=datetime.utcnow(); db.session.commit(); return jsonify({'valid':True,'bookstream_user_id':ss.bookstream_user_id,'risk_level':ss.risk_level})

@bp.post('/api/integration/session/revoke')
@service_required
def revoke_session():
    data=request.get_json(force=True) or {}; ss=SecuritySession.query.filter_by(session_id=data.get('security_session_id')).first()
    if not ss: return jsonify({'message':'not found'}),404
    now=datetime.utcnow(); ss.status='REVOKED'; ss.ended_at=now; ss.last_activity=now
    _event(ss.bookstream_user_id,'SESSION_END',ip_address=ss.ip_address,device_fingerprint=ss.device_fingerprint,user_agent=ss.user_agent,location=ss.location,session_id=ss.session_id,risk_score=ss.risk_score,risk_level=ss.risk_level,action='ENDED',reason=data.get('reason') or 'User logged out')
    db.session.commit(); return jsonify({'revoked':True,'ended_at':now.isoformat()})

@bp.post('/api/integration/session/start')
@service_required
def start_session():
    data=request.get_json(force=True) or {}; bid=str(data.get('bookstream_user_id',''))
    identity=SecurityIdentity.query.filter_by(bookstream_user_id=bid).first()
    if not identity: return jsonify({'message':'Security identity not found'}),404
    if identity.status!='ACTIVE': return jsonify({'message':'Account is restricted'}),403
    ip=data.get('ip_address') or '0.0.0.0'; fp=data.get('device_fingerprint') or ''; ua=data.get('user_agent','')
    score,level,reasons,anomaly,location=_risk_for(bid,ip,fp,ua)
    sid='CS-'+secrets.token_hex(24); now=datetime.utcnow()
    db.session.add(SecuritySession(session_id=sid,bookstream_user_id=bid,ip_address=ip,device_fingerprint=fp,user_agent=ua,location=location,risk_score=score,risk_level=level,created_at=now,last_activity=now))
    _event(bid,'SESSION_START',ip_address=ip,device_fingerprint=fp,user_agent=ua,location=location,session_id=sid,risk_score=score,anomaly_score=anomaly,risk_level=level,action='RUNNING',reason='BookStream session started')
    identity.last_seen=now; db.session.commit()
    return jsonify({'security_session_id':sid,'status':'ACTIVE','started_at':now.isoformat()})

@bp.get('/api/integration/analytics')
@service_required
def analytics():
    from sqlalchemy import func
    return jsonify({
        'users':SecurityIdentity.query.count(),
        'active_sessions':_active_session_count(),
        'failed_logins':SecurityEvent.query.filter_by(event_type='LOGIN_FAILED').count(),
        'book_views':SecurityEvent.query.filter_by(event_type='BOOK_VIEW').count(),
        'pdf_views':SecurityEvent.query.filter_by(event_type='PDF_VIEW').count(),
        'downloads':SecurityEvent.query.filter_by(event_type='PDF_DOWNLOAD').count(),
        'searches':SecurityEvent.query.filter_by(event_type='BOOK_SEARCH').count(),
        'bookmarks':SecurityEvent.query.filter(SecurityEvent.event_type.in_(['BOOKMARK_ADD','BOOKMARK_REMOVE'])).count(),
        'reviews':SecurityEvent.query.filter_by(event_type='REVIEW').count(),
        'ratings':SecurityEvent.query.filter_by(event_type='RATING').count(),
        'medium':SecurityEvent.query.filter_by(risk_level='MEDIUM').count(),
        'high':SecurityEvent.query.filter_by(risk_level='HIGH').count(),
        'critical':SecurityEvent.query.filter_by(risk_level='CRITICAL').count(),
        'threats':ThreatLog.query.count(),
        'honeypot':SecurityEvent.query.filter_by(event_type='HONEYPOT_TRIGGERED').count(),
        'blocked_sessions':SecuritySession.query.filter_by(status='REVOKED').count(),
        'pending_approvals':IntegrationAccessRequest.query.filter_by(status='PENDING').count(),
    })

@bp.get('/api/integration/users')
@service_required
def integration_users():
    users=SecurityIdentity.query.order_by(SecurityIdentity.last_seen.desc()).all()
    out=[]
    for u in users:
        sessions=_active_session_count(u.bookstream_user_id)
        ev=SecurityEvent.query.filter_by(bookstream_user_id=u.bookstream_user_id).order_by(SecurityEvent.timestamp.desc()).first()
        out.append({'bookstream_user_id':u.bookstream_user_id,'username':u.username,'email':u.email,'role':u.role,'status':u.status,'active_sessions':sessions,'risk_score':ev.risk_score if ev else 0,'risk_level':ev.risk_level if ev else 'LOW','last_active':u.last_seen.isoformat() if u.last_seen else None})
    return jsonify(out)

@bp.get('/api/integration/users/<user_id>/security')
@service_required
def user_security(user_id):
    u=SecurityIdentity.query.filter_by(bookstream_user_id=str(user_id)).first_or_404()
    events=SecurityEvent.query.filter_by(bookstream_user_id=str(user_id)).order_by(SecurityEvent.timestamp.desc()).limit(500).all()
    sessions=SecuritySession.query.filter_by(bookstream_user_id=str(user_id)).order_by(SecuritySession.last_activity.desc()).all()
    ips=sorted({e.ip_address for e in events if e.ip_address})
    devices=sorted({e.device_fingerprint for e in events if e.device_fingerprint})
    current=events[0] if events else None
    cutoff=datetime.utcnow()-SESSION_PRESENCE_WINDOW
    return jsonify({'identity':{'id':u.bookstream_user_id,'username':u.username,'email':u.email,'role':u.role,'status':u.status,'last_seen':u.last_seen.isoformat() if u.last_seen else None},'current':{'risk_score':current.risk_score if current else 0,'risk_level':current.risk_level if current else 'LOW','anomaly_score':current.anomaly_score if current else 0},'devices':devices,'ips':ips,'sessions':[{'id':s.session_id,'status':s.status,'presence':'ACTIVE' if s.status=='ACTIVE' and s.last_activity>=cutoff else 'INACTIVE','ip':s.ip_address,'device':s.device_fingerprint,'created_at':s.created_at.isoformat(),'last_activity':s.last_activity.isoformat(),'ended_at':s.ended_at.isoformat() if s.ended_at else None} for s in sessions],'events':[{'event_id':e.event_id,'type':e.event_type,'timestamp':e.timestamp.isoformat(),'ip':e.ip_address,'device':e.device_fingerprint,'location':e.location,'session_id':e.session_id,'resource_id':e.resource_id,'resource_name':e.resource_name,'risk_score':e.risk_score,'anomaly_score':e.anomaly_score,'risk_level':e.risk_level,'action':e.action,'reason':e.reason} for e in events]})

@bp.get('/api/integration/users/<user_id>/activity')
@service_required
def user_activity(user_id):
    events=SecurityEvent.query.filter_by(bookstream_user_id=str(user_id)).order_by(SecurityEvent.timestamp.desc()).limit(500).all()
    return jsonify([{'event_id':e.event_id,'type':e.event_type,'timestamp':e.timestamp.isoformat(),'resource_id':e.resource_id,'resource_name':e.resource_name,'risk_score':e.risk_score,'risk_level':e.risk_level,'action':e.action} for e in events])

@bp.get('/api/integration/users/<user_id>/audit')
@service_required
def user_audit(user_id):
    u=SecurityIdentity.query.filter_by(bookstream_user_id=str(user_id)).first_or_404()
    rows=AuditLog.query.filter_by(username=u.username).order_by(AuditLog.timestamp.desc()).limit(500).all()
    return jsonify([{'id':x.id,'timestamp':x.timestamp.isoformat(),'username':x.username,'device':x.device_id,'ip':x.ip_address,'location':x.country,'status':x.auth_status,'risk':x.risk_score,'admin_decision':x.admin_decision} for x in rows])


@bp.get('/bookstream-management')
def bookstream_management():
    from flask_login import current_user
    if not current_user.is_authenticated or current_user.role!='admin': abort(403)
    return render_template('bookstream_management.html')

@bp.get('/api/admin/bookstream/events')
def admin_bookstream_events():
    from flask_login import current_user
    if not current_user.is_authenticated or current_user.role != 'admin':
        return jsonify({'message': 'Admin required'}), 403
    rows = (db.session.query(SecurityEvent, SecurityIdentity.username)
            .outerjoin(SecurityIdentity, SecurityEvent.bookstream_user_id == SecurityIdentity.bookstream_user_id)
            .order_by(SecurityEvent.timestamp.desc())
            .limit(100)
            .all())
    return jsonify([{
        'event_id': event.event_id,
        'timestamp': event.timestamp.isoformat() if event.timestamp else None,
        'username': username or 'Unknown user',
        'event_type': event.event_type,
        'resource_name': event.resource_name,
        'reason': event.reason,
        'risk_score': event.risk_score,
        'risk_level': event.risk_level,
        'action': event.action,
    } for event, username in rows])

@bp.get('/bookstream-security')
def security_dashboard():
    # Existing Flask admin login protects the UI.
    from flask_login import current_user
    if not current_user.is_authenticated or current_user.role != 'admin': abort(403)
    return render_template('bookstream_security.html')

@bp.get('/bookstream-security/user/<user_id>')
def security_user_page(user_id):
    from flask_login import current_user
    if not current_user.is_authenticated or current_user.role != 'admin': abort(403)
    return render_template('bookstream_user.html', user_id=user_id)

@bp.post('/api/admin/integration/approval/<request_id>')
def admin_approval(request_id):
    from flask_login import current_user
    if not current_user.is_authenticated or current_user.role!='admin': return jsonify({'message':'Admin required'}),403
    ar=IntegrationAccessRequest.query.filter_by(request_id=request_id).first_or_404(); decision=(request.get_json(silent=True) or {}).get('decision')
    frozen_review=ar.request_type=='FROZEN_ACCOUNT_LOGIN'
    allowed=('UNFREEZE','KEEP_FROZEN') if frozen_review else ('APPROVE','DENY')
    if decision not in allowed: return jsonify({'message':'Invalid decision for this request'}),400
    if frozen_review and decision=='UNFREEZE':
        try:
            data=_bookstream_request('/api/integration/admin/users/'+str(ar.bookstream_user_id),'PATCH',{'status':'ACTIVE'})
        except Exception as exc:
            return jsonify({'message':f'Could not unfreeze the BookStream account: {exc}'}),502
        identity=SecurityIdentity.query.filter_by(bookstream_user_id=ar.bookstream_user_id).first()
        if identity: identity.status=data.get('status','ACTIVE'); identity.last_seen=datetime.utcnow()
        ar.status='APPROVED'; action_reason='Administrator unfroze the account and approved this sign-in.'
        _event(ar.bookstream_user_id,'ACCOUNT_UNFROZEN',action='ENABLED',reason='Administrator approved a frozen-account sign-in request')
    elif frozen_review:
        ar.status='DENIED'; action_reason='Administrator kept the account frozen; sign-in denied.'
    else:
        ar.status='APPROVED' if decision=='APPROVE' else 'DENIED'; action_reason=f'Admin {decision.lower()}ed access'
    ar.decided_by=current_user.id; ar.decided_at=datetime.utcnow()
    _event(ar.bookstream_user_id,'ADMIN_APPROVAL',ip_address=ar.ip_address,device_fingerprint=ar.device_fingerprint,location=ar.location,risk_score=ar.risk_score,anomaly_score=ar.anomaly_score,risk_level=ar.risk_level,action=ar.status,reason=action_reason)
    db.session.commit(); return jsonify({'status':ar.status})

@bp.get('/api/admin/integration/analytics')
def admin_analytics():
    from flask_login import current_user
    if not current_user.is_authenticated or current_user.role!='admin': return jsonify({'message':'Admin required'}),403
    # Same real counters as service analytics.
    return jsonify({
        'users':SecurityIdentity.query.count(),'active_sessions':_active_session_count(),
        'failed_logins':SecurityEvent.query.filter_by(event_type='LOGIN_FAILED').count(),'book_views':SecurityEvent.query.filter_by(event_type='BOOK_VIEW').count(),
        'pdf_views':SecurityEvent.query.filter_by(event_type='PDF_VIEW').count(),'downloads':SecurityEvent.query.filter_by(event_type='PDF_DOWNLOAD').count(),
        'searches':SecurityEvent.query.filter_by(event_type='BOOK_SEARCH').count(),'bookmarks':SecurityEvent.query.filter(SecurityEvent.event_type.in_(['BOOKMARK_ADD','BOOKMARK_REMOVE'])).count(),
        'reviews':SecurityEvent.query.filter_by(event_type='REVIEW').count(),'ratings':SecurityEvent.query.filter_by(event_type='RATING').count(),
        'medium':SecurityEvent.query.filter_by(risk_level='MEDIUM').count(),'high':SecurityEvent.query.filter_by(risk_level='HIGH').count(),'critical':SecurityEvent.query.filter_by(risk_level='CRITICAL').count(),
        'threats':ThreatLog.query.count(),'honeypot':SecurityEvent.query.filter_by(event_type='HONEYPOT_TRIGGERED').count(),'blocked_sessions':SecuritySession.query.filter_by(status='REVOKED').count(),'pending_approvals':IntegrationAccessRequest.query.filter_by(status='PENDING').count()})

@bp.get('/api/admin/integration/users')
def admin_users():
    from flask_login import current_user
    if not current_user.is_authenticated or current_user.role!='admin': return jsonify({'message':'Admin required'}),403
    users=SecurityIdentity.query.order_by(SecurityIdentity.last_seen.desc()).all(); out=[]
    for u in users:
        ev=SecurityEvent.query.filter_by(bookstream_user_id=u.bookstream_user_id).order_by(SecurityEvent.timestamp.desc()).first()
        out.append({'bookstream_user_id':u.bookstream_user_id,'username':u.username,'email':u.email,'role':u.role,'status':u.status,'active_sessions':_active_session_count(u.bookstream_user_id),'risk_score':ev.risk_score if ev else 0,'risk_level':ev.risk_level if ev else 'LOW','last_active':u.last_seen.isoformat() if u.last_seen else None})
    return jsonify(out)

@bp.get('/api/admin/integration/user/<user_id>')
def admin_user(user_id):
    from flask_login import current_user
    if not current_user.is_authenticated or current_user.role!='admin': return jsonify({'message':'Admin required'}),403
    u=SecurityIdentity.query.filter_by(bookstream_user_id=str(user_id)).first_or_404(); events=SecurityEvent.query.filter_by(bookstream_user_id=str(user_id)).order_by(SecurityEvent.timestamp.desc()).limit(500).all(); sessions=SecuritySession.query.filter_by(bookstream_user_id=str(user_id)).order_by(SecuritySession.last_activity.desc()).all(); cutoff=datetime.utcnow()-SESSION_PRESENCE_WINDOW
    return jsonify({'identity':{'id':u.bookstream_user_id,'username':u.username,'email':u.email,'role':u.role,'status':u.status,'last_seen':u.last_seen.isoformat() if u.last_seen else None},'events':[{'event_id':e.event_id,'type':e.event_type,'timestamp':e.timestamp.isoformat(),'ip':e.ip_address,'device':e.device_fingerprint,'location':e.location,'session_id':e.session_id,'resource_id':e.resource_id,'resource_name':e.resource_name,'metadata':_event_metadata(e),'risk_score':e.risk_score,'anomaly_score':e.anomaly_score,'risk_level':e.risk_level,'action':e.action,'reason':e.reason} for e in events],'sessions':[{'id':s.session_id,'status':s.status,'presence':'ACTIVE' if s.status=='ACTIVE' and s.last_activity>=cutoff else 'INACTIVE','ip':s.ip_address,'device':s.device_fingerprint,'created_at':s.created_at.isoformat(),'last_activity':s.last_activity.isoformat(),'ended_at':s.ended_at.isoformat() if s.ended_at else None} for s in sessions]})

@bp.get('/api/admin/integration/approvals')
def admin_integration_approvals():
    from flask_login import current_user
    if not current_user.is_authenticated or current_user.role!='admin': return jsonify({'message':'Admin required'}),403
    rows=IntegrationAccessRequest.query.order_by(IntegrationAccessRequest.created_at.desc()).limit(100).all()
    return jsonify([{'request_id':r.request_id,'username':r.username,'email':r.email,'risk_score':r.risk_score,'risk_level':r.risk_level,'location':r.location,'ip':r.ip_address,'status':r.status,'request_type':r.request_type,'created_at':r.created_at.isoformat(),'reasons':r.reasons} for r in rows])

@bp.patch('/api/admin/bookstream/user/<user_id>')
def admin_bookstream_user(user_id):
    from flask_login import current_user
    if not current_user.is_authenticated or current_user.role!='admin': return jsonify({'message':'Admin required'}),403
    try:
        payload=request.get_json(force=True) or {}; data=_bookstream_request('/api/integration/admin/users/'+str(user_id),'PATCH',payload)
        identity=SecurityIdentity.query.filter_by(bookstream_user_id=str(user_id)).first()
        if identity and data.get('status') in ('ACTIVE','FROZEN','BLOCKED'):
            identity.status=data['status']; identity.last_seen=datetime.utcnow()
            if data['status'] in ('FROZEN','BLOCKED'):
                now=datetime.utcnow()
                for ss in SecuritySession.query.filter_by(bookstream_user_id=str(user_id),status='ACTIVE').all():
                    ss.status='REVOKED'; ss.ended_at=now; ss.last_activity=now
                    _event(user_id,'SESSION_END',ip_address=ss.ip_address,device_fingerprint=ss.device_fingerprint,user_agent=ss.user_agent,location=ss.location,session_id=ss.session_id,risk_score=ss.risk_score,risk_level=ss.risk_level,action='REVOKED',reason='Account frozen by CloudSentinel administrator')
                _event(user_id,'ACCOUNT_FROZEN',action='ENFORCED',reason='BookStream access disabled by CloudSentinel administrator')
            else:
                _event(user_id,'ACCOUNT_UNFROZEN',action='ENABLED',reason='BookStream access restored by CloudSentinel administrator')
        db.session.add(AuditLog(username=current_user.username,device_id='CLOUDSENTINEL-ADMIN',browser='Admin Console',ip_address=request.remote_addr or '-',country='-',auth_status='BOOKSTREAM_ADMIN_ACTION',risk_score=0,admin_decision=str(payload))); db.session.commit(); return jsonify(data)
    except Exception as e: return jsonify({'message':str(e)}),502

@bp.get('/api/admin/bookstream/books')
def admin_bookstream_books():
    from flask_login import current_user
    if not current_user.is_authenticated or current_user.role!='admin': return jsonify({'message':'Admin required'}),403
    try: return jsonify(_bookstream_request('/api/integration/admin/books'))
    except Exception as e: return jsonify({'message':str(e)}),502

@bp.delete('/api/admin/bookstream/book/<book_id>')
def admin_bookstream_book(book_id):
    from flask_login import current_user
    if not current_user.is_authenticated or current_user.role!='admin': return jsonify({'message':'Admin required'}),403
    try:
        data=_bookstream_request('/api/integration/admin/books/'+str(book_id),'DELETE'); db.session.add(AuditLog(username=current_user.username,device_id='CLOUDSENTINEL-ADMIN',browser='Admin Console',ip_address=request.remote_addr or '-',country='-',auth_status='BOOK_DELETE',risk_score=0,admin_decision='DELETED')); db.session.commit(); return jsonify(data)
    except Exception as e: return jsonify({'message':str(e)}),502
