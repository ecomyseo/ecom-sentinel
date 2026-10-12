from PIL import Image, ImageDraw

S = 256
img = Image.new("RGBA", (S, S), (0, 0, 0, 0))
d = ImageDraw.Draw(img)

m = 0.09 * S
pts = [
    (S * 0.5, m),
    (S - m, S * 0.22),
    (S - m, S * 0.55),
    (S * 0.5, S - m),
    (m, S * 0.55),
    (m, S * 0.22),
]
# shield body + subtle border
d.polygon(pts, fill=(46, 139, 87, 255))
d.line(pts + [pts[0]], fill=(255, 255, 255, 255), width=int(S * 0.025), joint="curve")
# white checkmark
d.line(
    [(S * 0.32, S * 0.50), (S * 0.45, S * 0.64), (S * 0.70, S * 0.33)],
    fill=(255, 255, 255, 255),
    width=int(S * 0.10),
    joint="curve",
)

img.save("icon.ico", sizes=[(16, 16), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])
print("icon.ico creado")
