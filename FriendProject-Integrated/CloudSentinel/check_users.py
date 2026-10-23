from app import create_app
from models import User

app = create_app()
with app.app_context():
    users = User.query.all()
    print(f'Users in database: {len(users)}')
    for u in users:
        print(f'  - {u.username} ({u.email}), role: {u.role}')
    
    # Update admin email to match the requested email
    admin_user = User.query.filter_by(role='admin').first()
    if admin_user:
        admin_user.email = 'akhila8812@gmail.com'
        from extensions import db
        db.session.commit()
        print(f'\nUpdated admin email to: {admin_user.email}')
