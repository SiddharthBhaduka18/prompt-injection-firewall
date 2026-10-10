"""Find a Unicode TrueType font on Windows, macOS or Linux (used to render demo images and PDFs)."""
import os

CANDIDATES = [
    r"C:\Windows\Fonts\arial.ttf",
    r"C:\Windows\Fonts\segoeui.ttf",
    r"C:\Windows\Fonts\calibri.ttf",
    "/System/Library/Fonts/Supplemental/Arial.ttf",
    "/Library/Fonts/Arial.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
    "/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf",
]


def font_path():
    for p in CANDIDATES:
        if os.path.exists(p):
            return p
    return None


def pil_font(size):
    from PIL import ImageFont
    p = font_path()
    if p:
        return ImageFont.truetype(p, size)
    return ImageFont.load_default(size=size)  # Pillow >= 10.1
