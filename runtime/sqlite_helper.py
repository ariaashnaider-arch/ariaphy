import json
from pathlib import Path
import sqlite3
import sys


def main(args):
    if len(args) == 4 and args[:2] == ["-readonly", "-json"]:
        readonly, database, sql = True, *args[2:]
    elif len(args) == 2:
        readonly, database, sql = False, *args
    else:
        raise ValueError("Unsupported sqlite3 arguments.")

    mode = "ro" if readonly else "rw"
    uri = Path(database).resolve().as_uri() + "?mode=" + mode
    connection = sqlite3.connect(uri, uri=True, timeout=1.5)
    try:
        if readonly:
            connection.row_factory = sqlite3.Row
            rows = [dict(row) for row in connection.execute(sql)]
            if rows:
                print(json.dumps(rows, ensure_ascii=False, separators=(",", ":")))
        else:
            connection.executescript(sql)
    finally:
        connection.close()


if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except (OSError, ValueError, sqlite3.Error) as error:
        print(f"sqlite3: {error}", file=sys.stderr)
        sys.exit(1)
