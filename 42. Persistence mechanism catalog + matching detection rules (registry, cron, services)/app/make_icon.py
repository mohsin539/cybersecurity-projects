from PIL import Image, ImageDraw, ImageFont

SIZE = 256
img = Image.new("RGBA", (SIZE, SIZE), (0, 0, 0, 0))
draw = ImageDraw.Draw(img)

draw.polygon(
    [
        (128, 8),
        (248, 48),
        (248, 132),
        (248, 148),
        (248, 148),
        (182, 224),
        (128, 248),
        (74, 224),
        (8, 148),
        (8, 48),
    ],
    fill=(31, 56, 100, 255),
)
draw.polygon(
    [
        (128, 8),
        (248, 48),
        (248, 132),
        (248, 148),
        (248, 148),
        (182, 224),
        (128, 248),
        (74, 224),
        (8, 148),
        (8, 48),
    ],
    outline=(46, 117, 182, 255),
    width=6,
)
draw.rounded_rectangle((58, 58, 198, 198), radius=18, outline=(46, 117, 182, 255), width=8)

try:
    font = ImageFont.truetype("segoeuib.ttf", 110)
except Exception:
    font = ImageFont.load_default()

draw.text((128, 128), "P", font=font, fill=(255, 255, 255, 255), anchor="mm")
draw.text((128, 128), "P", font=font, fill=(255, 255, 255, 255), anchor="mm")

for size in (256, 128, 64, 48, 32, 16):
    img.copy().resize((size, size), Image.LANCZOS).save("pemcat.ico", append_images=[])

img.save("pemcat.ico", format="ICO", sizes=[(256, 256), (128, 128), (64, 64), (48, 48), (32, 32), (16, 16)])
print("icon written: pemcat.ico")