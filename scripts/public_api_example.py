import argparse
import json

from ida_nexus import DatabaseHandle

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Example of using the public API")
    parser.add_argument("database", help="Path to the IDB/executable to open")
    args = parser.parse_args()
    with DatabaseHandle.open(args.database) as handle:
        identity = handle.instance.health_identity()
        print(f"Database identity: {json.dumps(identity, indent=2)}")
        result = handle.execute_python("{'module': db.module, 'sha256': db.sha256}")[
            "result"
        ]
        print(f"Python result: {json.dumps(result, indent=2)}")
