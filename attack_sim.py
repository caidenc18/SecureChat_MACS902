
from server.database import get_connection


def setup_database(db):
    db.execute("""
        CREATE TABLE IF NOT EXISTS attack_backup (
            username TEXT PRIMARY KEY,
            original_key TEXT NOT NULL
        )
    """)


def spoof_key(target, attacker):
    with get_connection() as db:
        setup_database(db)

        # Get both users' public keys
        target_user = db.execute(
            "SELECT encryption_public_key FROM users WHERE username = ?",
            (target,)
        ).fetchone()

        attacker_user = db.execute(
            "SELECT encryption_public_key FROM users WHERE username = ?",
            (attacker,)
        ).fetchone()

        if not target_user or not attacker_user:
            print("Error: User not found.")
            return

        if target == attacker:
            print("Target and attacker must be different users.")
            return

        # Check whether an attack is already active
        backup = db.execute(
            "SELECT username FROM attack_backup WHERE username = ?",
            (target,)
        ).fetchone()

        if backup:
            print("Attack is already active. Restore the key first.")
            return

        # Save the original public key
        db.execute(
            "INSERT INTO attack_backup VALUES (?, ?)",
            (target, target_user["encryption_public_key"])
        )

        # Replace target's key with attacker's key
        db.execute(
            "UPDATE users SET encryption_public_key = ? WHERE username = ?",
            (attacker_user["encryption_public_key"], target)
        )

    print(f"\n[ATTACK] {target}'s public key has been replaced!")
    print(f"[ATTACK] Key copied from {attacker}.")


def restore_key(target):
    with get_connection() as db:
        setup_database(db)

        backup = db.execute(
            "SELECT original_key FROM attack_backup WHERE username = ?",
            (target,)
        ).fetchone()

        if not backup:
            print("No active attack found.")
            return

        # Restore the original public key
        db.execute(
            "UPDATE users SET encryption_public_key = ? WHERE username = ?",
            (backup["original_key"], target)
        )

        # Remove the backup
        db.execute(
            "DELETE FROM attack_backup WHERE username = ?",
            (target,)
        )

    print(f"\n[RESTORE] {target}'s original public key restored!")


def check_status():
    with get_connection() as db:
        setup_database(db)

        attacks = db.execute(
            "SELECT username FROM attack_backup"
        ).fetchall()

    if attacks:
        print("\nActive attacks:")
        for attack in attacks:
            print(f"- {attack['username']}")
    else:
        print("\nNo active attacks.")


if __name__ == "__main__":

    print("\n--- MITM Attack Simulation ---")
    print("1. Spoof public key")
    print("2. Restore public key")
    print("3. Check attack status")

    choice = input("\nChoose an option: ")

    if choice == "1":
        target = input("Target username: ")
        attacker = input("Attacker username: ")
        spoof_key(target, attacker)

    elif choice == "2":
        target = input("Target username: ")
        restore_key(target)

    elif choice == "3":
        check_status()

    else:
        print("Invalid option.")
