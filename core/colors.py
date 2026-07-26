"""
BYMA TOOLS - Terminal Colors & Output System
Sistem warna dan output untuk terminal
"""
from colorama import init, Fore, Back, Style
import sys
import os

init(autoreset=True)


class Colors:
    """Definisi warna terminal"""
    
    # Basic Colors
    RED = Fore.RED
    GREEN = Fore.GREEN
    YELLOW = Fore.YELLOW
    BLUE = Fore.BLUE
    MAGENTA = Fore.MAGENTA
    CYAN = Fore.CYAN
    WHITE = Fore.WHITE
    BLACK = Fore.BLACK
    RESET = Fore.RESET
    
    # Bright Colors
    BRED = Fore.LIGHTRED_EX
    BGREEN = Fore.LIGHTGREEN_EX
    BYELLOW = Fore.LIGHTYELLOW_EX
    BBLUE = Fore.LIGHTBLUE_EX
    BMAGENTA = Fore.LIGHTMAGENTA_EX
    BCYAN = Fore.LIGHTCYAN_EX
    BWHITE = Fore.LIGHTWHITE_EX
    BBLACK = Fore.LIGHTBLACK_EX
    
    # Background Colors
    BG_RED = Back.RED
    BG_GREEN = Back.GREEN
    BG_YELLOW = Back.YELLOW
    BG_BLUE = Back.BLUE
    BG_MAGENTA = Back.MAGENTA
    BG_CYAN = Back.CYAN
    BG_WHITE = Back.WHITE
    BG_BLACK = Back.BLACK
    
    # Style
    BRIGHT = Style.BRIGHT
    DIM = Style.DIM
    NORMAL = Style.RESET_ALL


# Singleton instance
colors = Colors()


def cprint(text, color=Colors.WHITE, end='\n', flush=True):
    """Print dengan warna"""
    try:
        print(f"{color}{text}{Colors.RESET}", end=end, flush=flush)
    except Exception:
        print(text, end=end, flush=flush)


def print_banner():
    """Menampilkan banner BYMA TOOLS"""
    try:
        banner = f"""
{Colors.BCYAN}{Colors.BRIGHT}+============================================================+
|                                                              |
|  {Colors.BGREEN} ####  ####  #  #  ####  #  #  ####                         |
|  #  #  #  #  #  #  #  #  #  #  #                            |
|  ####  ####  #  #  ####  #  #  ####                         |
|  #  #  #  #  #  #  #  #  #  #  #                            |
|  ####  #  #   ##   #  #   ##   ####                         |
|                                                              |
|  {Colors.BYELLOW}Multi-Purpose Cybersecurity Toolkit{Colors.BCYAN}                        |
|  {Colors.BWHITE}Version 1.0.0 | BYMA SECURITY{Colors.BCYAN}                              |
|                                                              |
+============================================================+{Colors.RESET}
"""
        print(banner)
    except Exception:
        print(f"{Colors.BCYAN}BYMA TOOLS - Multi-Purpose Cybersecurity Toolkit v1.0.0{Colors.RESET}")


def print_success(text):
    """Print pesan sukses"""
    cprint(f"[+] {text}", Colors.BGREEN)


def print_error(text):
    """Print pesan error"""
    cprint(f"[!] {text}", Colors.BRED)


def print_warning(text):
    """Print pesan warning"""
    cprint(f"[*] {text}", Colors.BYELLOW)


def print_info(text):
    """Print pesan info"""
    cprint(f"[i] {text}", Colors.BCYAN)


def print_debug(text):
    """Print pesan debug"""
    if os.environ.get("DEBUG"):
        cprint(f"[D] {text}", Colors.BBLACK)


def print_status(text):
    """Print pesan status"""
    cprint(f"[~] {text}", Colors.BMAGENTA)


def print_target(text):
    """Print target"""
    cprint(f"    Target: {text}", Colors.BWHITE)


def print_result(label, value, color=Colors.BWHITE):
    """Print hasil"""
    cprint(f"    {Colors.BCYAN}{label}: {color}{value}", Colors.RESET)


def print_table(headers, rows, widths=None):
    """Print tabel"""
    if not widths:
        widths = [max(len(str(h)), max((len(str(r[i])) for r in rows), default=0))
                  for i, h in enumerate(headers)]
    
    # Header
    header_line = " | ".join(f"{Colors.BCYAN}{h:<{widths[i]}}{Colors.RESET}"
                             for i, h in enumerate(headers))
    separator = "-+-".join("-" * w for w in widths)
    
    print(f"    {header_line}")
    print(f"    {separator}")
    
    # Rows
    for row in rows:
        row_line = " | ".join(f"{Colors.BWHITE}{str(row[i]):<{widths[i]}}{Colors.RESET}"
                              for i in range(len(headers)))
        print(f"    {row_line}")


def print_progress(current, total, prefix="", suffix=""):
    """Print progress bar"""
    bar_length = 40
    filled = int(bar_length * current / total)
    bar = "█" * filled + "░" * (bar_length - filled)
    percent = current / total * 100
    
    sys.stdout.write(f"\r    {prefix} [{Colors.BCYAN}{bar}{Colors.WHITE}] {percent:.1f}% {suffix}")
    sys.stdout.flush()


def print_separator(char="-", length=60, color=Colors.BBLACK):
    """Print separator line"""
    cprint(f"    {char * length}", color)


def print_section(title):
    """Print section header"""
    print()
    cprint(f"{'=' * 60}", Colors.BCYAN)
    cprint(f"  {title.upper()}", Colors.BGREEN + Colors.BRIGHT)
    cprint(f"{'=' * 60}", Colors.CYAN)
    print()


def clear_screen():
    """Clear terminal screen"""
    os.system('cls' if os.name == 'nt' else 'clear')


def pause():
    """Pause execution"""
    input(f"\n{Colors.BYELLOW}[*] Press Enter to continue...{Colors.RESET}")
