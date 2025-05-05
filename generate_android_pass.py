from PIL import Image, ImageDraw, ImageFont, ImageFilter
import qrcode
import os

def generate_enhanced_android_pass(user_name, user_id, commerce_name="Pizzeria Napoli", logo_path=None):
    # Créer le dossier static si besoin
    os.makedirs("static", exist_ok=True)
    output_file = f"static/unikard_android_{user_id}.png"

    # Créer QR code
    qr = qrcode.make(f"https://unikard.app/client/{user_id}")
    qr = qr.resize((140, 140))

    # Créer fond avec dégradé horizontal
    width, height = 480, 260
    background = Image.new("RGB", (width, height), "#1e1e2f")
    for x in range(width):
        for y in range(height):
            blend = int(30 + (x / width) * 50)
            background.putpixel((x, y), (blend, blend, blend + 20))

    draw = ImageDraw.Draw(background)

    # Police
    try:
        font_large = ImageFont.truetype("arial.ttf", 18)
        font_small = ImageFont.truetype("arial.ttf", 14)
    except:
        font_large = ImageFont.load_default()
        font_small = ImageFont.load_default()

    # Logo
    if logo_path and os.path.exists(logo_path):
        logo = Image.open(logo_path).convert("RGBA")
        logo.thumbnail((60, 60))
        background.paste(logo, (20, 20), logo)
    else:
        # Placeholder logo
        logo = Image.new("RGBA", (60, 60), (200, 200, 200, 255))
        draw_logo = ImageDraw.Draw(logo)
        draw_logo.ellipse((10, 10, 50, 50), fill=(120, 120, 120))
        background.paste(logo, (20, 20), logo)

    # Texte
    draw.text((100, 25), "Carte Unikard", font=font_large, fill="white")
    draw.text((100, 55), f"Nom : {user_name}", font=font_small, fill="white")
    draw.text((100, 75), f"ID : {user_id}", font=font_small, fill="white")
    draw.text((100, 95), f"Commerce : {commerce_name}", font=font_small, fill="white")

    # QR code encadré
    qr_box = Image.new("RGB", (qr.width + 8, qr.height + 8), (255, 255, 255))
    qr_box.paste(qr, (4, 4))
    background.paste(qr_box, (width - 160, 60))

    # Effet doux
    background = background.filter(ImageFilter.SMOOTH_MORE)

    # Sauvegarde
    background.save(output_file)
    return output_file

# Appel de test
generate_enhanced_android_pass("Paul", "123456")
