from app.main import create_app

app = create_app()

for r in app.routes:
    try:
        p = r.path
    except Exception:
        continue
    if 'reports' in str(p):
        print(p, getattr(r, 'methods', None))

