import os
import sys
from BluubeAuth import BluubeAuth

def _clear() -> None:
    os.system("cls" if os.name == "nt" else "clear")


def _header() -> None:
    print("BluubeAuth - Python Example")
    print("-" * 32)
    
def _format_date(iso_str: str) -> str:
    if not iso_str:
        return "Unknown"
    try:
        from datetime import datetime
        clean_str = iso_str.replace('Z', '+00:00')
        dt = datetime.fromisoformat(clean_str)
        local_dt = dt.astimezone()
        return local_dt.strftime('%d/%m/%Y - %H:%M:%S')
    except Exception:
        return str(iso_str)
    
def _print_user_data(auth: BluubeAuth) -> None:
    if not auth.user_data:
        return
    print("\nUser data: ")
    print("Username: " + str(auth.user_data.get("username", "Unknown")))
    print("IP address: " + str(auth.user_data.get("ip", "Unknown")))
    print("Hardware-Id: " + str(auth.user_data.get("hwid", "Unknown")))
    
    ca = auth.user_data.get("createdAt")
    ea = auth.user_data.get("expiresAt")
    print("Created at: " + _format_date(ca))
    print("Expires at: " + (_format_date(ea) if ea else "Lifetime"))
    print("-" * 32)

def main() -> None:
    # SDK PYTHON -> APP_ID, OWNER_ID, VERSION
    auth = BluubeAuth(app_id="APP_ID", owner_id="OWNER_ID", version="1.0")
    _clear()
    _header()
    if not auth.initialize():
        print("\n" + (auth.last_message or "Initialization failed."))
        input("\nPress ENTER to exit...")
        auth.close()
        return

    while True:
        _clear()
        _header()
        print("[1] Login (username/password)")
        print("[2] Register (license key + username + password)")
        print("[3] Exit")
        option = (input("Select: ") or "").strip()

        if option == "1":
            u = (input("Username: ") or "").strip()
            p = input("Password: ")
            ok = auth.login_user(u, p)
            _clear()
            _header()
            print("Authenticated" if ok else (auth.last_message or "Login failed."))
            if ok:
                _print_user_data(auth)
        elif option == "2":
            lk = (input("License key: ") or "").strip()
            ru = (input("Username: ") or "").strip()
            rp = input("Password: ")
            ok = auth.register_with_key(lk, ru, rp)
            _clear()
            _header()
            print("Registered and authenticated" if ok else (auth.last_message or "Registration failed."))
            if ok:
                _print_user_data(auth)
        elif option == "3":
            auth.close()
            return
        else:
            print("Invalid option.")

        input("\nPress ENTER to continue...")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
