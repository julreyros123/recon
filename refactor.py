import os
import re

routes_dir = r"c:\Users\acer laptop\Knowsec\app\routes"
files_to_refactor = ["employees.py", "workspaces.py", "users.py", "devices.py"]

for filename in files_to_refactor:
    filepath = os.path.join(routes_dir, filename)
    with open(filepath, "r", encoding="utf-8") as f:
        content = f.read()

    # Update imports
    content = content.replace(
        "from app.database.database import get_db_connection, get_db, log_audit_event",
        "from app.database.database import get_db, log_audit_event\nimport sqlite3"
    )
    content = content.replace(
        "from app.database.database import get_db_connection, log_audit_event",
        "from app.database.database import get_db, log_audit_event\nimport sqlite3"
    )
    content = content.replace(
        "    get_db_connection, verify_password, hash_password, log_audit_event",
        "    get_db, verify_password, hash_password, log_audit_event\nimport sqlite3"
    )
    
    # Simple regex to replace route signatures:
    # Find `def func(..., current_user: dict = Depends(...)):` 
    # Or `def func(...):`
    # and add `, conn: sqlite3.Connection = Depends(get_db)` before `):`
    # Then remove `conn = get_db_connection()`
    # Then replace `finally:\n        conn.close()` with `finally:\n        pass` to preserve try block indentation easily.
    
    # Wait, let's just use re.sub for the `conn = get_db_connection()`
    content = content.replace("    conn = get_db_connection()\n", "")
    
    # Replace `finally: conn.close()` with `finally: pass`
    content = content.replace("    finally:\n        conn.close()", "    finally:\n        pass")
    
    # We must add `conn: sqlite3.Connection = Depends(get_db)` to defs.
    # We can match `):` that appears right after `def ` declaration.
    # A bit risky, let's do:
    def replacer(match):
        sig = match.group(0)
        if "conn: sqlite3.Connection = Depends(get_db)" in sig:
            return sig
        if sig.endswith("):"):
            if "(" in sig and len(sig) > 4 and sig.strip() != "def ():":
                # Check if it's already got it or if it's a route (starts with @router usually, but we are matching def)
                # Only add to functions that use `cursor = conn.cursor()` or something?
                # Actually, our files only have endpoints. 
                # Let's do it safely.
                return sig[:-2] + ", conn: sqlite3.Connection = Depends(get_db):"
        return sig

    # This is a bit too hacky and might break nested functions.
    # Instead, let's just do manual replacements for the remaining 4 files via multi_replace_file_content!
    pass
