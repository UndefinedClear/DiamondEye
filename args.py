import argparse


def validate_data_size(value):
    try:
        size_str = value.lower().strip()
        if size_str.endswith('k') or size_str.endswith('kb'):
            int(size_str[:-1])
        elif size_str.endswith('m') or size_str.endswith('mb'):
            int(size_str[:-1])
        else:
            int(size_str)
        return value
    except (ValueError, TypeError):
        raise argparse.ArgumentTypeError("Invalid data size: use 1024, 64k, 1m")


def parse_args():
    parser = argparse.ArgumentParser(description="DiamondEye v6.7 — HTTP Load Tester")
    parser.add_argument('url', help='Target URL (e.g. http://127.0.0.1)')
    parser.add_argument('-w', '--workers', type=int, default=10)
    parser.add_argument('-s', '--sockets', type=int, default=500)
    parser.add_argument('-m', '--methods', help='GET,POST,PUT,PATCH,ALL')
    parser.add_argument('-u', '--useragents', help='User-Agent file')
    parser.add_argument('-n', '--no-ssl-check', action='store_true')
    parser.add_argument('--proxy')
    parser.add_argument('-d', '--debug', action='store_true')
    parser.add_argument('-l', '--log')
    parser.add_argument('--json')
    parser.add_argument('--plot')
    parser.add_argument('--http2', action='store_true')
    parser.add_argument('--junk', action='store_true')
    parser.add_argument('--random-host', action='store_true')
    parser.add_argument('--slow', type=float, default=0.0)
    parser.add_argument('--extreme', action='store_true')
    parser.add_argument('--data-size', type=validate_data_size, default="0")
    parser.add_argument('--flood', action='store_true')
    parser.add_argument('--path-fuzz', action='store_true')
    parser.add_argument('--header-flood', action='store_true')
    parser.add_argument('--method-fuzz', action='store_true')
    return parser.parse_args()
