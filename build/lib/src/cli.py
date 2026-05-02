import sys
import secrets
import questionary
import os
import time
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.live import Live
from rich.text import Text
from rich.theme import Theme
from rich.progress import Progress, SpinnerColumn, TextColumn

from .storage import (
    init_db,
    get_vault_salt,
    set_vault_salt,
    set_verification,
    get_verification,
    add_entry,
    list_entries,
    get_entry,
    delete_entry,
    list_vaults,
)
from .auth import Authenticator
from .crypto import CryptoEngine
from .models import MasterKey, Salt, Nonce, Ciphertext, Tag
from .session import session
from cryptography.exceptions import InvalidTag

# Professional Matrix/Gemini theme
custom_theme = Theme({
    "info": "bold #5fafff",       # Sky Blue
    "warning": "bold #dfaf00",    # Gold
    "error": "bold #ff5f5f",      # Soft Red
    "success": "bold #5fdf87",    # Emerald
    "vault": "bold #af87ff",      # Lavender
    "header": "bold #ffffff",     # White
    "dim": "bold #626262",        # Slate
})

console = Console(theme=custom_theme)

# Cleaner Questionary Style (No '?' mark)
custom_style = questionary.Style([
    ('qmark', 'fg:#000000'),      # Hide the question mark
    ('question', 'bold'),
    ('answer', 'fg:#5fdf87 bold'), # Emerald answer
    ('pointer', 'fg:#5fafff bold'), # Sky blue pointer
    ('highlighted', 'fg:#5fafff bold'),
    ('separator', 'fg:#444444'),
    ('instruction', 'fg:#888888 italic'),
])

def print_banner():
    creator_art = r"""
[info]        __    ___       _                      _     [/]
[info]  ____  / /_  / (_)   __(_)_____________ ______(_)____[/]
[info] / __ \/ __ \/ / / | / / / ___/ ___/ __ `/ ___/ / ___/[/]
[info]/ /_/ / /_/ / / /| |/ / (__  ) /__/ /_/ / /  / (__  ) [/]
[info]\____/_.___/_/_/ |___/_/____/\___/\__,_/_/  /_/____/  [/]"""

    banner = f"""
[header]  ██████╗ ██╗    ██╗███╗   ███╗ █████╗ ███╗   ██╗[/]
[header]  ██╔══██╗██║    ██║████╗ ████║██╔══██╗████╗  ██║[/]
[header]  ██████╔╝██║ █╗ ██║██╔████╔██║███████║██╔██╗ ██║[/]
[header]  ██╔═══╝ ██║███╗██║██║╚██╔╝██║██╔══██║██║╚██╗██║[/]
[header]  ██║     ╚███╔███╔╝██║ ╚═╝ ██║██║  ██║██║ ╚████║[/]
[header]  ╚═╝      ╚══╝╚══╝     ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝[/]
[dim]          Minimal Local Password Manager[/]
[dim]              Created by:[/]{creator_art}
    """
    console.print(Panel.fit(banner, border_style="dim"))

def _check_keypress():
    """Non-blocking keypress detection."""
    try:
        if os.name == 'nt':
            import msvcrt
            if msvcrt.kbhit():
                msvcrt.getch()
                return True
        else:
            import select
            if select.select([sys.stdin], [], [], 0)[0]:
                sys.stdin.read(1)
                return True
    except:
        pass
    return False

def _get_master_key() -> Optional[MasterKey]:
    if not session.db_path:
        return None
    
    if session.check_timeout():
        console.print("\n[warning]Session expired. Vault locked.[/]")
    
    if session.master_key:
        session.refresh()
        return session.master_key
    
    salt = get_vault_salt(session.db_path)
    verification = get_verification(session.db_path)
    
    while True:
        password = questionary.password(f"Master Password [{session.db_path}]:", style=custom_style, qmark="").ask()
        if not password: return None
            
        with console.status("[bold info]Verifying..."):
            key = Authenticator.derive_key(password, salt)
            if verification:
                engine = CryptoEngine(key)
                try:
                    engine.decrypt(Nonce(verification["nonce"]), Ciphertext(verification["ciphertext"]), Tag(verification["tag"]))
                    session.master_key = key
                    session.refresh()
                    return key
                except InvalidTag:
                    console.print("[error]Invalid password.[/]")
                    if not questionary.confirm("Try again?", style=custom_style, qmark="").ask(): return None
            else:
                session.master_key = key
                session.refresh()
                return key

def cmd_create_vault():
    name = questionary.text("Vault Name:", style=custom_style, qmark="").ask()
    if not name: return
    if not name.endswith(".db"): name += ".db"
    
    if os.path.exists(name):
        console.print(f"[error]Vault '{name}' already exists.[/]")
        return

    password = questionary.password("Set Master Password:", style=custom_style, qmark="").ask()
    confirm = questionary.password("Confirm Master Password:", style=custom_style, qmark="").ask()
    
    if password != confirm:
        console.print("[error]Passwords do not match.[/]")
        return

    with console.status("[bold success]Initializing..."):
        init_db(name)
        salt = Salt(secrets.token_bytes(16))
        set_vault_salt(salt, name)
        key = Authenticator.derive_key(password, salt)
        engine = CryptoEngine(key)
        v_nonce, v_ct, v_tag = engine.encrypt(b"PWMAN_VERIFY")
        set_verification(v_nonce, v_ct, v_tag, name)

    console.print(f"[success]Vault '{name}' created![/]")
    console.print(Panel(f"[warning]BACKUP SALT (HEX):[/]\n[bold #dfaf00]{salt.hex()}[/]", border_style="warning"))
    
    if questionary.confirm("Open this vault?", style=custom_style, qmark="").ask():
        session.db_path = name
        session.master_key = key
        session.refresh()

def cmd_open_vault():
    vaults = list_vaults()
    if not vaults:
        console.print("[error]No vaults found.[/]")
        return

    choice = questionary.select("Select Vault:", choices=vaults + ["Back"], style=custom_style, qmark="").ask()
    if choice and choice != "Back":
        session.db_path = choice
        session.master_key = None
        if _get_master_key():
            console.print(f"[success]Vault '{choice}' is active.[/]")

def cmd_delete_vault():
    vaults = list_vaults()
    if not vaults: return
    choice = questionary.select("Delete Vault:", choices=vaults + ["Cancel"], style=custom_style, qmark="").ask()
    if choice and choice != "Cancel":
        if questionary.confirm(f"PERMANENTLY delete '{choice}'?", style=custom_style, qmark="").ask():
            os.remove(choice)
            if session.db_path == choice: session.clear()
            console.print(f"[success]Deleted {choice}.[/]")

def cmd_add_entry():
    key = _get_master_key()
    if not key: return
    engine = CryptoEngine(key)
    name = questionary.text("Entry Name:", style=custom_style, qmark="").ask()
    username = questionary.text("Username:", style=custom_style, qmark="").ask()
    secret = questionary.password("Secret:", style=custom_style, qmark="").ask()
    if not all([name, username, secret]):
        console.print("[error]Missing fields.[/]")
        return
    with console.status("[bold success]Saving..."):
        nonce, ciphertext, tag = engine.encrypt(secret.encode())
        add_entry(name, username, nonce, ciphertext, tag, session.db_path)
    session.refresh()
    console.print(f"[success]Saved '{name}'.[/]")

def cmd_list_entries():
    entries = list_entries(session.db_path)
    if not entries:
        console.print("[info]No entries.[/]")
        return
    table = Table(title=f"Vault Content: {session.db_path}", show_header=True, header_style="info")
    table.add_column("ID", style="dim", width=4)
    table.add_column("Name", style="header")
    table.add_column("Username", style="success")
    for e in entries:
        table.add_row(str(e['id']), e['name'], e['username'])
    console.print(table)
    choice = questionary.text("ID to view (empty to exit):", style=custom_style, qmark="").ask()
    if choice and choice.isdigit():
        cmd_view_entry(int(choice))

def cmd_view_entry(entry_id: int):
    row = get_entry(entry_id, session.db_path)
    if not row:
        console.print("[error]Not found.[/]")
        return
    key = _get_master_key()
    if not key: return
    engine = CryptoEngine(key)
    try:
        pt = engine.decrypt(Nonce(row["nonce"]), Ciphertext(row["ciphertext"]), Tag(row["tag"]))
        
        start_time = time.time()
        timeout = 10
        
        with Live(console=console, refresh_per_second=10) as live:
            while True:
                elapsed = time.time() - start_time
                remaining = max(0, int(timeout - elapsed))
                
                panel = Panel(
                    f"[header]Secret:[/] [black on success] {pt.decode()} [/]\n\n"
                    f"[dim]Destructing in [warning]{remaining}s[/]... Press Enter to clear now.[/]",
                    title=f"Viewing: {row['name']}",
                    border_style="success"
                )
                live.update(panel)
                
                if elapsed >= timeout or _check_keypress():
                    break
                time.sleep(0.05)
            # Update to cleared state
            live.update(Panel("[success]Secret cleared from display.[/]", border_style="success"))
        
        session.refresh()
    except InvalidTag:
        console.print("[error]Decryption failed.[/]")

def cmd_delete_entry():
    entries = list_entries(session.db_path)
    if not entries: return
    choices = [f"{e['id']}: {e['name']}" for e in entries] + ["Back"]
    choice = questionary.select("Delete Entry:", choices=choices, style=custom_style, qmark="").ask()
    if choice and choice != "Back":
        entry_id = int(choice.split(":")[0])
        if questionary.confirm("Delete?", style=custom_style, qmark="").ask():
            delete_entry(entry_id, session.db_path)
            session.refresh()
            console.print("[success]Deleted.[/]")

def cmd_settings():
    while True:
        action = questionary.select(
            "Settings",
            choices=[f"Change Auto-Lock Timeout (Current: {session.timeout_seconds}s)", "Back"],
            style=custom_style, qmark=""
        ).ask()
        if action == "Back" or action is None: break
        elif "Timeout" in action:
            new_val = questionary.text("New timeout (seconds):", style=custom_style, qmark="").ask()
            if new_val and new_val.isdigit():
                session.timeout_seconds = int(new_val)
                console.print(f"[success]Timeout updated to {new_val}s.[/]")

def main():
    console.clear()
    print_banner()
    while True:
        # Check auto-lock
        if session.check_timeout():
            if session.master_key:
                session.master_key = None
                console.print("\n[warning]Session expired. Vault locked.[/]")
        
        v_status = f"[vault]{session.db_path}[/]" if session.db_path else "[error]None[/]"
        locked = "[warning]Locked[/]" if (session.db_path and not session.master_key) else "[success]Active[/]" if session.db_path else ""
        
        console.print(f"\n[bold white]Vault:[/] {v_status} {locked}")
        
        # Context-aware flattened menu
        if not session.db_path:
            choices = ["Open Vault", "Create Vault", "Delete Vault", "Settings", "Exit"]
        else:
            choices = ["List/View Entries", "Add Entry", "Delete Entry", "Lock/Close Vault", "Settings", "Exit"]
            
        action = questionary.select(
            "Gemini Shell",
            choices=choices,
            style=custom_style,
            qmark=""
        ).ask()

        # Update last activity
        if action: 
            session.refresh()
            
        if action == "Create Vault": cmd_create_vault()
        elif action == "Open Vault": cmd_open_vault()
        elif action == "Delete Vault": cmd_delete_vault()
        elif action == "List/View Entries": cmd_list_entries()
        elif action == "Add Entry": cmd_add_entry()
        elif action == "Delete Entry": cmd_delete_entry()
        elif action == "Lock/Close Vault": 
            session.clear()
            console.print("[info]Vault closed.[/]")
        elif action == "Settings": cmd_settings()
        elif action == "Exit" or action is None:
            console.print("[italic info]Session terminated. Stay secure.[/]")
            break

if __name__ == "__main__":
    main()
