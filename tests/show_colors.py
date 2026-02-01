#!/usr/bin/env python3
"""Show all standard ANSI colors as they appear in your terminal."""

def sgr(code):
    return f"\033[{code}m"

RESET = sgr(0)
BOLD = sgr(1)
DIM = sgr(2)

print()
print("=" * 60)
print("  YOUR TERMINAL'S ANSI COLORS")
print("=" * 60)
print()

# Standard colors (30-37)
print("STANDARD FOREGROUND (30-37):")
print()
for i, name in enumerate(["Black", "Red", "Green", "Yellow", "Blue", "Magenta", "Cyan", "White"]):
    code = 30 + i
    print(f"  {sgr(code)}████████ {name:8} ({code}){RESET}  │  {sgr(code)}Sample text here{RESET}")
print()

# Bright colors (90-97)
print("BRIGHT FOREGROUND (90-97):")
print()
for i, name in enumerate(["Black/Grey", "Red", "Green", "Yellow", "Blue", "Magenta", "Cyan", "White"]):
    code = 90 + i
    print(f"  {sgr(code)}████████ {name:10} ({code}){RESET}  │  {sgr(code)}Sample text here{RESET}")
print()

# Bullet separator preview
print("=" * 60)
print("  BULLET SEPARATOR PREVIEW")
print("=" * 60)
print()

samples = [
    ("Grey (90)", 90),
    ("Cyan (36)", 36),
    ("Bright Cyan (96)", 96),
    ("Blue (34)", 34),
    ("Magenta (35)", 35),
    ("White (37)", 37),
]

for name, code in samples:
    bullet = f"{sgr(code)}•{RESET}"
    print(f"  CPU  {bullet}  45%  {bullet}  2.4GHz       ── {name}")
print()

# With dim attribute
print("WITH DIM ATTRIBUTE:")
print()
for name, code in [("Dim Cyan (2;36)", "2;36"), ("Dim Grey (2;90)", "2;90"), ("Dim White (2;37)", "2;37")]:
    bullet = f"{sgr(code)}•{RESET}"
    print(f"  CPU  {bullet}  45%  {bullet}  2.4GHz       ── {name}")
print()

# Montauk-style preview
print("=" * 60)
print("  MONTAUK STYLE PREVIEW")
print("=" * 60)
print()

grey = sgr(90)
green = sgr(32)
yellow = sgr(33)
red = sgr(31)
cyan = sgr(36)

for bullet_name, bullet_code in [("Grey", 90), ("Cyan", 36), ("Dim Cyan", "2;36")]:
    b = f"{sgr(bullet_code)}•{RESET}"
    print(f"  [{bullet_name} bullets]")
    print(f"  {grey}│{RESET} PLIMIT    45% UTIL {b} 250W                    {grey}│{RESET}")
    print(f"  {grey}│{RESET} MEM       {green}████████{RESET}░░░░  62% {b} 20GB/32GB    {grey}│{RESET}")
    print(f"  {grey}│{RESET} /dev/sda  {yellow}██████████{RESET}░░  78% {b} 450G/500G    {grey}│{RESET}")
    print(f"  {grey}│{RESET} GPU       {red}███████████{RESET}░  92% {b} 11GB/12GB    {grey}│{RESET}")
    print()

print("=" * 60)
