"""Merge cover + body into the final PDF, normalizing to A4, with metadata."""
from pypdf import PdfReader, PdfWriter, Transformation

A4_W, A4_H = 595.28, 841.89

def normalize(page):
    box = page.mediabox
    w, h = float(box.width), float(box.height)
    # Force every page to exact A4 (tolerance 0.1pt) for size consistency
    if abs(w - A4_W) > 0.1 or abs(h - A4_H) > 0.1:
        sx, sy = A4_W / w, A4_H / h
        page.add_transformation(Transformation().scale(sx=sx, sy=sy))
        page.mediabox.lower_left = (0, 0)
        page.mediabox.upper_right = (A4_W, A4_H)
    return page

writer = PdfWriter()
# Cover = page 1
writer.add_page(normalize(PdfReader('C:/Users/moyoo/DropoutJeep/_cover.pdf').pages[0]))
# Body pages follow
for p in PdfReader('C:/Users/moyoo/DropoutJeep/_body.pdf').pages:
    writer.add_page(normalize(p))

writer.add_metadata({
    '/Title': 'Joomla Compromise Assessment — Discovery Meeting Guide',
    '/Author': 'Z.ai',
    '/Creator': 'Z.ai',
    '/Subject': 'Incident response discovery meeting guide for a compromised Joomla website',
    '/Keywords': 'Joomla, incident response, compromise assessment, forensics, discovery',
})

out = 'C:/Users/moyoo/DropoutJeep/Joomla_Compromise_Assessment_Discovery_Guide.pdf'
with open(out, 'wb') as f:
    writer.write(f)
print('MERGED_OK', out, len(writer.pages), 'pages')
