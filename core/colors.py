"""
BYMA TOOLS - Terminal Colors & Output System
Sistem warna dan output untuk terminal dengan tema cyber
"""
from colorama import init, Fore, Back, Style
import sys
import os
import time

init(autoreset=True)


class Colors:
    """Definisi warna terminal"""
    RED = Fore.RED
    GREEN = Fore.GREEN
    YELLOW = Fore.YELLOW
    BLUE = Fore.BLUE
    MAGENTA = Fore.MAGENTA
    CYAN = Fore.CYAN
    WHITE = Fore.WHITE
    BLACK = Fore.BLACK
    RESET = Fore.RESET
    BRED = Fore.LIGHTRED_EX
    BGREEN = Fore.LIGHTGREEN_EX
    BYELLOW = Fore.LIGHTYELLOW_EX
    BBLUE = Fore.LIGHTBLUE_EX
    BMAGENTA = Fore.LIGHTMAGENTA_EX
    BCYAN = Fore.LIGHTCYAN_EX
    BWHITE = Fore.LIGHTWHITE_EX
    BBLACK = Fore.LIGHTBLACK_EX
    BG_RED = Back.RED
    BG_GREEN = Back.GREEN
    BG_YELLOW = Back.YELLOW
    BG_BLUE = Back.BLUE
    BG_MAGENTA = Back.MAGENTA
    BG_CYAN = Back.CYAN
    BG_WHITE = Back.WHITE
    BG_BLACK = Back.BLACK
    BRIGHT = Style.BRIGHT
    DIM = Style.DIM
    NORMAL = Style.RESET_ALL


colors = Colors()


class Icons:
    """ASCII-safe icons untuk semua platform"""
    SUCCESS = "[+]"
    ERROR = "[-]"
    WARNING = "[*]"
    INFO = "[i]"
    LOADING = "..."
    ARROW = ">>"
    BULLET = "*"
    STAR = "*"
    SHIELD = "[#]"
    LOCK = "[L]"
    UNLOCK = "[U]"
    KEY = "[K]"
    TARGET = "[>]"
    SCAN = "[S]"
    GLOBE = "[W]"
    COMPUTER = "[C]"
    SERVER = "[=]"
    DATABASE = "[DB]"
    FILE = "[F]"
    FOLDER = "[D]"
    NETWORK = "[N]"
    CHAIN = ">>"
    CODE = "[/]"
    TERMINAL = ">"
    CHECK = "[OK]"
    CROSS = "[X]"
    RADIO_ON = "(*)"
    RADIO_OFF = "( )"
    TOOL = "[T]"


icons = Icons()


# ==================== ASCII ART BANNER ====================

BANNER_ASCII = r"""
      ____               _ __    __ ____  ____  ___    ____
     / __ )____ _____  (_) /   / // __ \/ __ \/   |  / __ \
    / __  / __ `/ __ \/ / /   / // / / / / / / /| | / / / /
   / /_/ / /_/ / / / / / /___/ // /_/ / /_/ / __ |/ /_/ /
  /_____/\__,_/_/ /_/_/_/_____/_/____/\____/_/  |_/_____/

"""


def cprint(text, color=Colors.WHITE, end='\n', flush=True):
    """Print dengan warna - safe untuk semua platform"""
    try:
        print(f"{color}{text}{Colors.RESET}", end=end, flush=flush)
    except UnicodeEncodeError:
        safe_text = text.encode('ascii', 'replace').decode('ascii')
        print(f"{color}{safe_text}{Colors.RESET}", end=end, flush=flush)
    except Exception:
        print(text, end=end, flush=flush)


def print_banner():
    """Menampilkan banner BYMA TOOLS dengan tema cyber"""
    try:
        print(f"{Colors.BCYAN}{Colors.BRIGHT}")
        print("=" * 62)
        print()
        print(f"  {Colors.BGREEN}{BANNER_ASCII}{Colors.BCYAN}")
        print(f"  {Colors.BYELLOW}  [>] Multi-Purpose Cybersecurity Toolkit{Colors.BCYAN}")
        print(f"  {Colors.BWHITE}  [i] Version 1.0.0 | BYMA SECURITY{Colors.BCYAN}")
        print()
        print("=" * 62)
        print(f"{Colors.RESET}")
    except Exception:
        print(f"{Colors.BCYAN}{'=' * 62}{Colors.RESET}")
        print(f"{Colors.BGREEN}  BYMA TOOLS - Multi-Purpose Cybersecurity Toolkit{Colors.RESET}")
        print(f"{Colors.BWHITE}  Version 1.0.0 | BYMA SECURITY{Colors.RESET}")
        print(f"{Colors.BCYAN}{'=' * 62}{Colors.RESET}")


def print_success(text):
    """Print pesan sukses"""
    cprint(f"  {icons.SUCCESS} {text}", Colors.BGREEN)


def print_error(text):
    """Print pesan error"""
    cprint(f"  {icons.ERROR} {text}", Colors.BRED)


def print_warning(text):
    """Print pesan warning"""
    cprint(f"  {icons.WARNING} {text}", Colors.BYELLOW)


def print_info(text):
    """Print pesan info"""
    cprint(f"  {icons.INFO} {text}", Colors.BCYAN)


def print_debug(text):
    """Print pesan debug"""
    if os.environ.get("DEBUG"):
        cprint(f"  {icons.BULLET} {text}", Colors.BBLACK)


def print_status(text):
    """Print pesan status"""
    cprint(f"  {icons.LOADING} {text}", Colors.BMAGENTA)


def print_target(text):
    """Print target"""
    cprint(f"\n  {icons.TARGET} Target: {Colors.BWHITE}{text}{Colors.RESET}", Colors.BCYAN)


def print_result(label, value, color=Colors.BWHITE):
    """Print hasil"""
    cprint(f"  {icons.ARROW} {Colors.BCYAN}{label}: {color}{value}", Colors.RESET)


def print_table(headers, rows, widths=None):
    """Print tabel dengan tema ASCII"""
    if not widths:
        widths = [max(len(str(h)), max((len(str(r[i])) for r in rows), default=0))
                  for i, h in enumerate(headers)]
    
    # Top border
    top = "  +" + "+".join("-" * (w + 2) for w in widths) + "+"
    print(f"{Colors.BCYAN}{top}{Colors.RESET}")
    
    # Header
    header_cells = "|".join(f" {Colors.BCYAN}{Colors.BRIGHT}{h:^{widths[i]}}{Colors.RESET} " 
                            for i, h in enumerate(headers))
    print(f"  {Colors.BCYAN}|{Colors.RESET}{header_cells}{Colors.BCYAN}|{Colors.RESET}")
    
    # Separator
    sep = "+" + "+".join("=" * (w + 2) for w in widths) + "+"
    print(f"{Colors.BCYAN}{sep}{Colors.RESET}")
    
    # Rows
    for row in rows:
        row_cells = "|".join(f" {Colors.BWHITE}{str(row[i]):^{widths[i]}}{Colors.RESET} " 
                            for i in range(len(headers)))
        print(f"  {Colors.BCYAN}|{Colors.RESET}{row_cells}{Colors.BCYAN}|{Colors.RESET}")
    
    # Bottom border
    bottom = "  +" + "+".join("-" * (w + 2) for w in widths) + "+"
    print(f"{Colors.BCYAN}{bottom}{Colors.RESET}")


def print_progress(current, total, prefix="", suffix="", bar_length=40):
    """Print progress bar"""
    filled = int(bar_length * current / total)
    bar = "#" * filled + "-" * (bar_length - filled)
    percent = current / total * 100
    
    sys.stdout.write(f"\r  {prefix} {Colors.BCYAN}[{Colors.BGREEN}{bar}{Colors.BCYAN}] {Colors.BWHITE}{percent:.1f}% {suffix}{Colors.RESET}")
    sys.stdout.flush()
    
    if current == total:
        print()


def print_separator(char="=", length=60, color=Colors.BCYAN):
    """Print separator line"""
    cprint(f"  {color}{char * length}{Colors.RESET}")


def print_section(title):
    """Print section header"""
    print()
    print(f"  {Colors.BCYAN}+{'=' * 58}+{Colors.RESET}")
    print(f"  {Colors.BCYAN}|{Colors.BGREEN}{Colors.BRIGHT}  {icons.ARROW} {title.upper():^52}  {Colors.BCYAN}|{Colors.RESET}")
    print(f"  {Colors.BCYAN}+{'=' * 58}+{Colors.RESET}")
    print()


def print_subsection(title):
    """Print subsection header"""
    cprint(f"\n  {Colors.BYELLOW}{icons.ARROW} {title}{Colors.RESET}", Colors.BYELLOW)
    cprint(f"  {Colors.BYELLOW}{'-' * 50}{Colors.RESET}", Colors.BYELLOW)


def print_box(text, color=Colors.BCYAN, width=60):
    """Print text dalam box"""
    lines = text.split('\n')
    max_len = max(len(line) for line in lines) if lines else 0
    box_width = max(width, max_len + 4)
    
    print(f"  {color}+{'-' * (box_width - 2)}+{Colors.RESET}")
    for line in lines:
        padding = box_width - 4 - len(line)
        if padding < 0:
            padding = 0
        print(f"  {color}| {Colors.BWHITE}{line}{' ' * padding} {color}|{Colors.RESET}")
    print(f"  {color}+{'-' * (box_width - 2)}+{Colors.RESET}")


def clear_screen():
    """Clear terminal screen"""
    os.system('cls' if os.name == 'nt' else 'clear')


def pause():
    """Pause execution"""
    cprint(f"\n  {icons.INFO} Press Enter to continue...", Colors.BYELLOW)
    input()


def print_loader(text="Loading", duration=2):
    """Print loading animation"""
    frames = ["|", "/", "-", "\\"]
    end_time = time.time() + duration
    
    while time.time() < end_time:
        for frame in frames:
            sys.stdout.write(f"\r  {Colors.BCYAN}[{frame}] {text}...{Colors.RESET}")
            sys.stdout.flush()
            time.sleep(0.1)
    
    sys.stdout.write(f"\r  {Colors.BGREEN}{icons.SUCCESS} {text} Complete!{Colors.RESET}\n")
    sys.stdout.flush()


def print_scan_start(target, tool):
    """Print scan starting info"""
    print()
    print(f"  {Colors.BCYAN}+{'=' * 58}+{Colors.RESET}")
    print(f"  {Colors.BCYAN}|{Colors.BGREEN}  {icons.SHIELD} SCAN INITIATED {'-' * 41}{Colors.BCYAN}|{Colors.RESET}")
    print(f"  {Colors.BCYAN}+{'-' * 58}+{Colors.RESET}")
    print(f"  {Colors.BCYAN}|{Colors.BWHITE}  {icons.TARGET} Target:  {Colors.BYELLOW}{target:<42}{Colors.BCYAN}|{Colors.RESET}")
    print(f"  {Colors.BCYAN}|{Colors.BWHITE}  {icons.TOOL} Tool:    {Colors.BGREEN}{tool:<42}{Colors.BCYAN}|{Colors.RESET}")
    print(f"  {Colors.BCYAN}|{Colors.BWHITE}  {icons.INFO} Status:  {Colors.BBLUE}Running...{' ' * 33}{Colors.BCYAN}|{Colors.RESET}")
    print(f"  {Colors.BCYAN}+{'=' * 58}+{Colors.RESET}")
    print()


def print_scan_complete(target, results_count):
    """Print scan completed info"""
    print()
    print(f"  {Colors.BCYAN}+{'=' * 58}+{Colors.RESET}")
    print(f"  {Colors.BCYAN}|{Colors.BGREEN}  {icons.SUCCESS} SCAN COMPLETED {'-' * 41}{Colors.BCYAN}|{Colors.RESET}")
    print(f"  {Colors.BCYAN}+{'-' * 58}+{Colors.RESET}")
    print(f"  {Colors.BCYAN}|{Colors.BWHITE}  {icons.TARGET} Target:  {Colors.BYELLOW}{target:<42}{Colors.BCYAN}|{Colors.RESET}")
    print(f"  {Colors.BCYAN}|{Colors.BWHITE}  {icons.FILE} Results: {Colors.BGREEN}{str(results_count):<42}{Colors.BCYAN}|{Colors.RESET}")
    print(f"  {Colors.BCYAN}|{Colors.BWHITE}  {icons.INFO} Status:  {Colors.BGREEN}{'Success!':<42}{Colors.BCYAN}|{Colors.RESET}")
    print(f"  {Colors.BCYAN}+{'=' * 58}+{Colors.RESET}")
    print()


def print_vuln_found(vuln_type, severity, location):
    """Print vulnerability found"""
    severity_colors = {
        "CRITICAL": Colors.BRED,
        "HIGH": Colors.RED,
        "MEDIUM": Colors.BYELLOW,
        "LOW": Colors.BCYAN,
        "INFO": Colors.BWHITE
    }
    color = severity_colors.get(severity, Colors.BWHITE)
    
    print(f"  {Colors.BRED}+--- {icons.WARNING} VULNERABILITY FOUND {'-' * 36}+{Colors.RESET}")
    print(f"  {Colors.BRED}|{Colors.BWHITE}  Type:     {color}{vuln_type:<43}{Colors.BRED}|{Colors.RESET}")
    print(f"  {Colors.BRED}|{Colors.BWHITE}  Severity: {color}{severity:<43}{Colors.BRED}|{Colors.RESET}")
    print(f"  {Colors.BRED}|{Colors.BWHITE}  Location: {Colors.BYELLOW}{location:<43}{Colors.BRED}|{Colors.RESET}")
    print(f"  {Colors.BRED}+{'-' * 57}+{Colors.RESET}")


def print_header(title):
    """Print header dengan tema"""
    print()
    print(f"  {Colors.BCYAN}{'=' * 60}{Colors.RESET}")
    print(f"  {Colors.BGREEN}{Colors.BRIGHT}  {icons.SHIELD} {title.upper()}{Colors.RESET}")
    print(f"  {Colors.BCYAN}{'=' * 60}{Colors.RESET}")
    print()


def print_footer():
    """Print footer"""
    print()
    print(f"  {Colors.BCYAN}{'-' * 60}{Colors.RESET}")
    print(f"  {Colors.BBLACK}  {icons.SHIELD} BYMA TOOLS v1.0.0 | {icons.INFO} Use responsibly{Colors.RESET}")
    print(f"  {Colors.BCYAN}{'-' * 60}{Colors.RESET}")
