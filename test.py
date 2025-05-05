from PIL import Image
import qrcode

img = qrcode.make("https://google.com")
img.save("qr_test.png")
print("✅ QR code généré.")