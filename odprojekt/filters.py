import markdown
import bleach
from markupsafe import Markup

ALLOWED_TAGS = [
    'p', 'strong', 'em', 'ul', 'ol', 'li', 'a', 'img', 'blockquote', 'code',
    'pre', 'br', 'hr', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6'
]
ALLOWED_ATTRIBUTES = {
    'a': ['href', 'title'],
    'img': ['src', 'alt', 'title'],
}

def markdown_to_html(md_text):
    html = markdown.markdown(md_text, extensions=['extra', 'sane_lists'])

    cleaned_html = bleach.clean(
        html,
        tags=ALLOWED_TAGS,
        attributes=ALLOWED_ATTRIBUTES,
        strip=True  
    )

    return Markup(cleaned_html)
