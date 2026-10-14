import argparse
import json
from .scanner import report


def main():
    parser = argparse.ArgumentParser(description='Scan Python source for common security risks')
    parser.add_argument('target', help='Python file or project directory')
    parser.add_argument('--json', dest='json_path', help='Save findings to a JSON file')
    args = parser.parse_args()
    try:
        data = report(args.target)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    for item in data['findings']:
        print(f"[{item['severity'].upper()}] {item['file']}:{item['line']} "
              f"{item['rule']} - {item['message']}")
    print(f"Found {data['finding_count']} potential issue(s).")
    if args.json_path:
        with open(args.json_path, 'w', encoding='utf-8') as handle:
            json.dump(data, handle, indent=2)
        print(f'Report saved to {args.json_path}')


if __name__ == '__main__':
    main()
