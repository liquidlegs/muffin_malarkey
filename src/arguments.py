from src.shared import IocType, AllIndicators
from src.shared import is_path_or_argment, get_regex

def parse_arguments(arg: str, _type: IocType):
    argument_type = is_path_or_argment(arg)
    output = []

    match _type:
        
        case IocType.IP:
            output = get_regex(arg, IocType.IP, argument_type)
        
        case IocType.URL:
            output = get_regex(arg, IocType.URL, argument_type)
        
        case IocType.DOMAIN:
            output = get_regex(arg, IocType.DOMAIN, argument_type)
        
        case IocType.HASH:
            output = get_regex(arg, IocType.HASH, argument_type)
        
        case IocType.ANY:
            output = get_regex(arg, IocType.ANY, argument_type)

    print("")
    print(argument_type)
    
    if type(output) == AllIndicators:
        keys = output.__dict__.keys()
        output_dict = output.__dict__

        for i in keys:
            print(i)

            for idx in output_dict[i]:
                print(f"\t{idx}")
    else:
        for i in output:
            print(i)