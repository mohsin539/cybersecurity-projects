"""Generate assets/app_icon.ico (flat forensic-recovery glyph)."""

from __future__ import annotations

import os
from PIL import Image, ImageDraw

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(os.path.dirname(HERE), "assets", "app_icon.ico")

W = 256
img = Image.new("RGBA", (W, W), (0, 0, 0, 0))
d = ImageDraw.Draw(img)

# background: rounded square, subtle vertical gradient
bg = Image.new("RGBA", (W, W), (0, 0, 0, 0))
bd = ImageDraw.Draw(bg)
top = (13, 17, 40)
bot = (27, 43, 84)
for y in range(W):
    t = y / W
    c = tuple(int(top[i] + (bot[i] - top[i]) * t) for i in range(3))
    bd.line([(0, y), (W, y)], fill=c + (255,))
mask = Image.new("L", (W, W), 0)
md = ImageDraw.Draw(mask)
md.rounded_rectangle([12, 12, W - 12, W - 12], radius=52, fill=255)
img.paste(bg, (0, 0), mask)

# hard-drive platter (stylised) in the background
d.ellipse([58, 60, 198, 200], fill=(15, 23, 42, 200), outline=(64, 102, 166, 255), width=4)
d.ellipse([96, 98, 160, 162], fill=(19, 31, 56, 200), outline=(64, 102, 166, 140), width=3)
d.ellipse([120, 122, 136, 138], fill=(94, 234, 212, 255))

# magnifier (usage lens) over the disc — teal ring + handle
ring = Image.new("RGBA", (W, W), (0, 0, 0, 0))
rd = ImageDraw.Draw(ring)
rd.ellipse([40, 40, 160, 160], outline=(45, 212, 191, 255), width=12)
rd.ellipse([40, 40, 160, 160], outline=(90, 250, 230, 120), width=26)
ring = ring.rotate(-22, expand=False)
img.alpha_composite(ring)
d.line([170, 170, 210, 210], fill=(45, 212, 191, 255), width=14)
d.line([170, 170, 210, 210], fill=(130, 255, 240, 90), width=7)

# recovery spark accent (orange)
d.line([128, 128, 150, 150], fill=(255, 167, 38, 255), width=9)
d.line([150, 150, 128, 150], fill=(255, 167, 38, 255), width=9)
d.line([150, 150, 150, 128], fill=(255, 167, 38, 255), width=9)
d.ellipse([188, 52, 214, 78], fill=(255, 167, 38, 255))

os.makedirs(os.path.dirname(OUT), exist_ok=True)
img.save(OUT, format="ICO",
         sizes=[(256, 256), (128, 128), (64, 64), (48, 48), (32, 32), (16, 16)])
print("wrote", OUT)