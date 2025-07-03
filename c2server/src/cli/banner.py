import colorama
from colorama import Fore, Style, Back
import pyfiglet

class SshadeBannerAdvanced:
    @staticmethod
    def display():
        colorama.init(autoreset=True) # Initialize Colorama for auto-resetting colors

        # Define a more C2-framework friendly color palette
        # Deeper, more subdued tones with focused accents
        ACCENT_BLUE = Fore.CYAN + Style.BRIGHT # For highlights, like a cursor or network activity
        DEEP_BLUE = Fore.BLUE + Style.DIM     # For background elements or subtle lines
        CRITICAL_RED = Fore.RED + Style.BRIGHT # For warnings or key identifiers
        SUBTLE_GRAY = Fore.WHITE + Style.DIM   # For general text or separators
        DIM_WHITE = Fore.WHITE + Style.BRIGHT # For main text, slightly muted
        MID_GRAY = Fore.LIGHTBLACK_EX + Style.BRIGHT # A slightly darker gray

        RESET = Style.RESET_ALL

        # --- Pyfiglet configuration ---
        text_to_render = "SShade"
        # "cybermedium", "doom", "modular", "digital" often work well for C2 themes
        font_choice = "cybermedium" # Clean, technical, and modern

        try:
            figlet_banner = pyfiglet.figlet_format(text_to_render, font=font_choice)
        except pyfiglet.FontNotFound:
            print(f"{CRITICAL_RED}Error: Font '{font_choice}' not found. Falling back to default.{RESET}")
            figlet_banner = pyfiglet.figlet_format(text_to_render) # Fallback to default

        banner_lines = figlet_banner.splitlines()

        # --- Banner Construction ---
        print(f"\n{MID_GRAY}{'='*70}{RESET}")
        print(f"{ACCENT_BLUE}   >>> {DIM_WHITE}SShade {CRITICAL_RED}C2 {ACCENT_BLUE}Framework {SUBTLE_GRAY}// OPERATIONAL {ACCENT_BLUE}<<< {RESET}")
        print(f"{MID_GRAY}{'='*70}{RESET}\n")

        # Apply colors to the SShade text, creating a subtle gradient or alternating effect
        for i, line in enumerate(banner_lines):
            if i % 2 == 0:
                print(f"{DIM_WHITE} {line}{RESET}") # Main text color
            else:
                print(f"{ACCENT_BLUE} {line}{RESET}") # Accent color

        print(f"\n{MID_GRAY}{'-'*70}{RESET}")
        print(f"{SUBTLE_GRAY}  > {ACCENT_BLUE}Secure & Covert Operations {CRITICAL_RED}| {SUBTLE_GRAY}Initializing Modules...{RESET}")
        print(f"{MID_GRAY}{'-'*70}{RESET}\n")