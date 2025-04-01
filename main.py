from argparse import ArgumentParser
from src.shared import IocType
from src.arguments import parse_arguments
from src.arguments import show_config, show_features, toggle_features

def main():
    parser = ArgumentParser(description="none")
    parser.add_argument("-i", "--ip", action="store")
    parser.add_argument("-u", "--url", action="store")
    parser.add_argument("-d", "--domain", action="store")
    parser.add_argument("-H", "--hash", action="store")
    parser.add_argument("-a", "--any", action="store")
    parser.add_argument("-T", "--toggle", action="store")
    parser.add_argument("-s", "--show-config", action="store_true")
    parser.add_argument("-F", "--show-features", action="store_true")
    parser.add_argument("--debug", action="store_true")
    
    args = parser.parse_args()

    if args.toggle != None:
        toggle_features(args.toggle)

    if args.show_config == True:
        show_config()
        show_features()

    if args.ip != None:
        parse_arguments(args.ip, IocType.IP)
    elif args.url != None:
        parse_arguments(args.url, IocType.URL)
    elif args.domain != None:
        parse_arguments(args.domain, IocType.DOMAIN)
    elif args.hash != None:
        parse_arguments(args.hash, IocType.HASH)
    elif args.any != None:
        parse_arguments(args.any, IocType.ANY)


if __name__ == "__main__":
    main()