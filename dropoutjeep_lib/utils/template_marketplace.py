"""Built-in template marketplace seeding and helpers."""

import json
import pathlib
from dropoutjeep_lib import db
from dropoutjeep_lib.models import EmailTemplate

DATA_DIR = pathlib.Path(__file__).parent.parent / 'data' / 'templates'


def seed_builtin_templates():
    """Load built-in templates from JSON files and sync DB records."""
    if not DATA_DIR.exists():
        return 0
    
    # Remove old built-in templates to replace with fresh contextual designs
    EmailTemplate.query.filter_by(is_builtin=True).delete(synchronize_session=False)
    db.session.commit()

    count = 0
    for path in sorted(DATA_DIR.glob('*.json')):
        try:
            data = json.loads(path.read_text(encoding='utf-8'))
        except Exception:
            continue
        name = data.get('name')
        if not name:
            continue
        t = EmailTemplate(
            name=name,
            category=data.get('category', 'custom'),
            description=data.get('description', ''),
            subject=data.get('subject', ''),
            body_html=data.get('body_html', ''),
            landing_html=data.get('landing_html', ''),
            author=data.get('author', 'DropoutJeep'),
            source_url=data.get('source_url'),
            is_builtin=True,
        )
        tags = data.get('tags')
        if isinstance(tags, list):
            t.set_tags(tags)
        db.session.add(t)
        count += 1
    if count:
        db.session.commit()
        print(f'[seed] re-seeded {count} built-in templates')
    return count


def get_categories():
    rows = db.session.query(EmailTemplate.category).distinct().all()
    return sorted(r[0] for r in rows)
