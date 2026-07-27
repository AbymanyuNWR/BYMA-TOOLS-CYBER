"""
BYMA TOOLS - Terminal Colors & Output System
Sistem warna dan output untuk tema cyber profesional
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
    SKULL = "(X)"
    CYBER = "@@"


icons = Icons()


# ==================== ASCII ART LOGO ====================

LOGO_SKULL = r"""
          _____
         /     \
        / () () \
        \  ___  /
         |     |
         |  _  |
         |_____|
        /|     |\
       / |     | \
      /  |_____|  \
     /____     ____\
          |   |
          |   |
          |___|
"""

LOGO_BYMA = r"""
   ____  ___  ____  ________    ______ ____  ___    ____
  | __ )/ _ \| __ )|__  / _ \  / ____/ __ \/   |  / __ \
  |  _ \ | | |  _ \ / / |_) || |   | |  / /| | | / / / /
  | |_) | |_| | |_) / /|  _ < | |___| |__/ / | |/ /_/ /
  |____/ \___/|____/___|_| \_\\______\____/  |_/_____/
"""

LOGO_CYBER_FULL = r"""
       _____                    _____   _____ ____  _     _     _
      / ____|                  |  __ \ / ____/ __ \| |   | |   | |
     | (___   _ __ ___  _   _ | |__) | |   | |  | | |   | |   | |
      \___ \ | '_ ` _ \| | | ||  ___/| |   | |  | | |   | |   | |
      ____) || | | | | | |_| || |    | |___| |__| | |___| |___| |____
     |_____/ |_| |_| |_|\__,_||_|     \_____\____/ \_____\____/|______|
"""

LOGO_CYBER_SMALL = r"""
   _____  _____ ____  _____    ____   ___  __  __
  / ____||/ ____/ __ \|  __ \  | __ ) / _ \|  \/  |
 | (___  | (___| |  | | |__) | |  _ \| | | | |\/| |
  \___ \ |    \  __/|  _  /  | |_) | |_| | |  | |
  ____) || |___| |   | | \ \  |  __/|  _/| |  | |
 |_____/  \_____|_|   |_|  \_\ |_|   |_| |_|  |_|
"""

LOGO_CYBER_ART = r"""
      ____  _  _  ____  ____  ____  ____
     (  _ \( \( )(  _ \( ___)(_  _)( ___)
      ) _ < )  (  )(_) ))__)   )(   )__)
     (____/(_)\_)(____/(____) (__) (____)
"""

SKULL_FULL = r"""
                        ________________
                       /                \
                      /                  \
                     /    ____________    \
                    |    /            \    |
                    |   |   O      O   |   |
                    |   |      <>      |   |
                    |   |     \__/     |   |
                    |    \            /    |
                    |     \__________/     |
                     \                    /
                      \    \        /    /
                       \    \      /    /
                        \    \    /    /
                         \    \  /    /
                          \    \/    /
                           \        /
                            \      /
                             \    /
                              \  /
                               \/
"""

SKULL_MINI = r'''
    .-""""-.
   /        \
  |  O    O  |
  |    <>    |
  |   \__/   |
   \        /
    '-....-'
'''

SKULL_CROSS = r"""
       ___________
      /           \
     /  O       O  \
    |      <>      |
    |     /  \     |
    |    '----'    |
     \            /
      \__________/
        |  ||  |
        |  ||  |
"""

# Combined Logo: Skull + BYMA CYBER
LOGO_MAIN = f"""
{SKULL_CROSS}

    ____  ___  ____  ________    ______ ____  ___    ____
   | __ )/ _ \\| __ )|__  / _ \\  / ____/ __ \\   |  / __ \\
   |  _ \\ | | |  _ \\ / / |_) || |   | |  / /| | | / / / /
   | |_) | |_| | |_) / /|  _ < | |___| |__/ / | |/ /_/ /
   |____/ \\___/|____/___|_| \\_\\\\______\\____/  |_/_____/

"""

# Short version for inline display
LOGO_SHORT = f"""
    {SKULL_MINI}   BYMA CYBER  v1.0.0
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
    """Menampilkan banner BYMA CYBER dengan tengkorak"""
    try:
        clear_screen()
        print()
        print(f"  {Colors.BRED}{Colors.BRIGHT}{'=' * 62}{Colors.RESET}")
        print(f"  {Colors.BRED}{Colors.BRIGHT}|{' ' * 60}|{Colors.RESET}")
        
        # Skull with crossbones
        skull_lines = SKULL_CROSS.split('\n')
        for line in skull_lines:
            if line.strip():
                padding = 62 - len(line) - 2
                print(f"  {Colors.BRED}|{Colors.BCYAN}{Colors.BRIGHT}  {line}{' ' * max(0, padding)}  {Colors.BRED}|{Colors.RESET}")
        
        print(f"  {Colors.BRED}|{' ' * 60}|{Colors.RESET}")
        
        # BYMA CYBER text
        cyber_lines = LOGO_BYMA.strip().split('\n')
        for line in cyber_lines:
            if line.strip():
                padding = 62 - len(line) - 2
                print(f"  {Colors.BRED}|{Colors.BGREEN}{Colors.BRIGHT}  {line}{' ' * max(0, padding)}  {Colors.BRED}|{Colors.RESET}")
        
        print(f"  {Colors.BRED}|{' ' * 60}|{Colors.RESET}")
        
        # CYBER subtitle
        print(f"  {Colors.BRED}|{Colors.BYELLOW}{Colors.BRIGHT}  {'C Y B E R   S E C U R I T Y   T O O L K I T':^60}  {Colors.BRED}|{Colors.RESET}")
        print(f"  {Colors.BRED}|{' ' * 60}|{Colors.RESET}")
        
        # Version info
        print(f"  {Colors.BRED}|{Colors.BWHITE}  {'Version 1.0.0 | Professional Edition':^60}  {Colors.BRED}|{Colors.RESET}")
        print(f"  {Colors.BRED}|{' ' * 60}|{Colors.RESET}")
        
        print(f"  {Colors.BRED}|{'=' * 60}|{Colors.RESET}")
        print(f"  {Colors.BRED}{Colors.BRIGHT}{'=' * 62}{Colors.RESET}")
        print(f"{Colors.RESET}")
        
    except Exception:
        print(f"{Colors.BCYAN}{'=' * 62}{Colors.RESET}")
        print(f"{Colors.BGREEN}  BYMA CYBER - Cybersecurity Toolkit{Colors.RESET}")
        print(f"{Colors.BWHITE}  Version 1.0.0 | Professional Edition{Colors.RESET}")
        print(f"{Colors.BCYAN}{'=' * 62}{Colors.RESET}")


def print_banner_login():
    """Banner untuk halaman login"""
    try:
        print()
        print(f"  {Colors.BCYAN}{Colors.BRIGHT}{'=' * 50}{Colors.RESET}")
        print()
        
        skull_lines = SKULL_MINI.split('\n')
        for line in skull_lines:
            if line.strip():
                print(f"  {Colors.BCYAN}{Colors.BRIGHT}  {line}{Colors.RESET}")
        
        print()
        print(f"  {Colors.BGREEN}{Colors.BRIGHT}{'BYMA CYBER':^50}{Colors.RESET}")
        print(f"  {Colors.BYELLOW}{'Security Toolkit v1.0.0':^50}{Colors.RESET}")
        print()
        print(f"  {Colors.BCYAN}{Colors.BRIGHT}{'=' * 50}{Colors.RESET}")
        print()
        
    except Exception:
        print(f"{Colors.BCYAN}{'=' * 50}{Colors.RESET}")
        print(f"{Colors.BGREEN}  BYMA CYBER{Colors.RESET}")
        print(f"{Colors.BCYAN}{'=' * 50}{Colors.RESET}")


def print_banner_tool(tool_name, description=""):
    """Banner untuk tool-specific"""
    try:
        print()
        print(f"  {Colors.BCYAN}+{'=' * 56}+{Colors.RESET}")
        print(f"  {Colors.BCYAN}|{Colors.BRED}{Colors.BRIGHT}  {SKULL_MINI.split(chr(10))[1]:^54}  {Colors.BCYAN}|{Colors.RESET}")
        print(f"  {Colors.BCYAN}|{Colors.BGREEN}{Colors.BRIGHT}  {tool_name.upper():^54}  {Colors.BCYAN}|{Colors.RESET}")
        if description:
            print(f"  {Colors.BCYAN}|{Colors.BYELLOW}  {description:^54}  {Colors.BCYAN}|{Colors.RESET}")
        print(f"  {Colors.BCYAN}|{Colors.BWHITE}  {'BYMA CYBER v1.0.0':^54}  {Colors.BCYAN}|{Colors.RESET}")
        print(f"  {Colors.BCYAN}+{'=' * 56}+{Colors.RESET}")
        print()
    except Exception:
        print(f"\n  {Colors.BCYAN}[{tool_name}]{Colors.RESET}\n")


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


def print_table(headers_or_table, rows=None, widths=None):
    """Print tabel dengan tema ASCII profesional"""
    if rows is None:
        headers = headers_or_table[0]
        rows = headers_or_table[1:]
    else:
        headers = headers_or_table
    if not widths:
        widths = [max(len(str(h)), max((len(str(r[i])) for r in rows), default=0))
                  for i, h in enumerate(headers)]
    
    # Top border
    top = "  +" + "+".join("=" * (w + 2) for w in widths) + "+"
    print(f"{Colors.BCYAN}{top}{Colors.RESET}")
    
    # Header
    header_cells = []
    for i, h in enumerate(headers):
        header_cells.append(f" {Colors.BCYAN}{Colors.BRIGHT}{h:^{widths[i]}}{Colors.RESET} ")
    print(f"  {Colors.BCYAN}|{'|'.join(header_cells)}|{Colors.RESET}")
    
    # Separator
    sep = "+" + "+".join("-" * (w + 2) for w in widths) + "+"
    print(f"{Colors.BCYAN}{sep}{Colors.RESET}")
    
    # Rows
    for row in rows:
        row_cells = []
        for i in range(len(headers)):
            cell_val = str(row[i]) if i < len(row) else ""
            row_cells.append(f" {Colors.BWHITE}{cell_val:^{widths[i]}}{Colors.RESET} ")
        print(f"  {Colors.BCYAN}|{'|'.join(row_cells)}|{Colors.RESET}")
    
    # Bottom border
    bottom = "  +" + "+".join("=" * (w + 2) for w in widths) + "+"
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
    """Print section header dengan style profesional"""
    print()
    print(f"  {Colors.BCYAN}+{'=' * 56}+{Colors.RESET}")
    print(f"  {Colors.BCYAN}|{Colors.BGREEN}{Colors.BRIGHT}  {icons.SHIELD} {title.upper():^50}  {Colors.BCYAN}|{Colors.RESET}")
    print(f"  {Colors.BCYAN}+{'=' * 56}+{Colors.RESET}")
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
    print(f"  {Colors.BCYAN}+{'=' * 56}+{Colors.RESET}")
    print(f"  {Colors.BCYAN}|{Colors.BRED}{Colors.BRIGHT}  {icons.SKULL} SCAN INITIATED {' ' * 39}  {Colors.BCYAN}|{Colors.RESET}")
    print(f"  {Colors.BCYAN}+{'-' * 56}+{Colors.RESET}")
    print(f"  {Colors.BCYAN}|{Colors.BWHITE}  {icons.TARGET} Target:  {Colors.BYELLOW}{target:<40}  {Colors.BCYAN}|{Colors.RESET}")
    print(f"  {Colors.BCYAN}|{Colors.BWHITE}  {icons.TOOL} Tool:    {Colors.BGREEN}{tool:<40}  {Colors.BCYAN}|{Colors.RESET}")
    print(f"  {Colors.BCYAN}|{Colors.BWHITE}  {icons.INFO} Status:  {Colors.BBLUE}{'Running...':<40}  {Colors.BCYAN}|{Colors.RESET}")
    print(f"  {Colors.BCYAN}+{'=' * 56}+{Colors.RESET}")
    print()


def print_scan_complete(target, results_count):
    """Print scan completed info"""
    print()
    print(f"  {Colors.BCYAN}+{'=' * 56}+{Colors.RESET}")
    print(f"  {Colors.BCYAN}|{Colors.BGREEN}{Colors.BRIGHT}  {icons.SUCCESS} SCAN COMPLETED {' ' * 39}  {Colors.BCYAN}|{Colors.RESET}")
    print(f"  {Colors.BCYAN}+{'-' * 56}+{Colors.RESET}")
    print(f"  {Colors.BCYAN}|{Colors.BWHITE}  {icons.TARGET} Target:  {Colors.BYELLOW}{target:<40}  {Colors.BCYAN}|{Colors.RESET}")
    print(f"  {Colors.BCYAN}|{Colors.BWHITE}  {icons.FILE} Results: {Colors.BGREEN}{str(results_count):<40}  {Colors.BCYAN}|{Colors.RESET}")
    print(f"  {Colors.BCYAN}|{Colors.BWHITE}  {icons.INFO} Status:  {Colors.BGREEN}{'Success!':<40}  {Colors.BCYAN}|{Colors.RESET}")
    print(f"  {Colors.BCYAN}+{'=' * 56}+{Colors.RESET}")
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
    print(f"  {Colors.BGREEN}{Colors.BRIGHT}  {icons.SKULL} {title.upper()}{Colors.RESET}")
    print(f"  {Colors.BCYAN}{'=' * 60}{Colors.RESET}")
    print()


def print_footer():
    """Print footer"""
    print()
    print(f"  {Colors.BCYAN}{'-' * 60}{Colors.RESET}")
    print(f"  {Colors.BBLACK}  {icons.SKULL} BYMA CYBER v1.0.0 | {icons.INFO} Use responsibly{Colors.RESET}")
    print(f"  {Colors.BCYAN}{'-' * 60}{Colors.RESET}")


def print_menu_header():
    """Print menu header"""
    print()
    print(f"  {Colors.BCYAN}+{'=' * 56}+{Colors.RESET}")
    print(f"  {Colors.BCYAN}|{Colors.BRED}{Colors.BRIGHT}              .---.       .---.              {Colors.BCYAN}|{Colors.RESET}")
    print(f"  {Colors.BCYAN}|{Colors.BRED}{Colors.BRIGHT}             /     \\     /     \\             {Colors.BCYAN}|{Colors.RESET}")
    print(f"  {Colors.BCYAN}|{Colors.BRED}{Colors.BRIGHT}            / () () \\   / () () \\            {Colors.BCYAN}|{Colors.RESET}")
    print(f"  {Colors.BCYAN}|{Colors.BRED}{Colors.BRIGHT}            \\  ___  /   \\  ___  /            {Colors.BCYAN}|{Colors.RESET}")
    print(f"  {Colors.BCYAN}|{Colors.BRED}{Colors.BRIGHT}             |     |     |     |             {Colors.BCYAN}|{Colors.RESET}")
    print(f"  {Colors.BCYAN}|{Colors.BRED}{Colors.BRIGHT}             |  _  |     |  _  |             {Colors.BCYAN}|{Colors.RESET}")
    print(f"  {Colors.BCYAN}|{Colors.BRED}{Colors.BRIGHT}             |_____|     |_____|             {Colors.BCYAN}|{Colors.RESET}")
    print(f"  {Colors.BCYAN}|{Colors.BGREEN}{Colors.BRIGHT}          ____  ___  ____  ________       {Colors.BCYAN}|{Colors.RESET}")
    print(f"  {Colors.BCYAN}|{Colors.BGREEN}{Colors.BRIGHT}         | __ )/ _ \\| __ )|__  / _ \\      {Colors.BCYAN}|{Colors.RESET}")
    print(f"  {Colors.BCYAN}|{Colors.BGREEN}{Colors.BRIGHT}         |  _ \\ | | |  _ \\ / / |_) |     {Colors.BCYAN}|{Colors.RESET}")
    print(f"  {Colors.BCYAN}|{Colors.BGREEN}{Colors.BRIGHT}         | |_) | |_| | |_) / /|  _ <      {Colors.BCYAN}|{Colors.RESET}")
    print(f"  {Colors.BCYAN}|{Colors.BGREEN}{Colors.BRIGHT}         |____/ \\___/|____/___|_| \\_\\     {Colors.BCYAN}|{Colors.RESET}")
    print(f"  {Colors.BCYAN}|{Colors.BYELLOW}{Colors.BRIGHT}              C Y B E R                      {Colors.BCYAN}|{Colors.RESET}")
    print(f"  {Colors.BCYAN}|{Colors.BWHITE}       Security Toolkit - v1.0.0            {Colors.BCYAN}|{Colors.RESET}")
    print(f"  {Colors.BCYAN}+{'=' * 56}+{Colors.RESET}")
    print()
