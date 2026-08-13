import sys

from ida_domain import Database


def run(db: Database):
    sys.stdout.write("Hello from IDA stdout!\n")
    sys.stderr.write("Hello from IDA stderr!\n")
    return {
        "module": db.module,
        "sha256": db.sha256,
    }
