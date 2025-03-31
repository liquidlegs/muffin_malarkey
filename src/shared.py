from enum import Enum
import os
import re
from dataclasses import dataclass

@dataclass
class AllIndicators:
    ip: list[str]
    url: list[str]
    domain: list[str]
    hash: list[str]

class IocType(Enum):
    IP = 0
    URL = 1
    DOMAIN = 2
    HASH = 3
    ANY = 4

class ArgumentType(Enum):
    PATH = 0
    LIST = 1
    ARGUMENT = 2

def is_path_or_argment(argument: str) -> ArgumentType | None:
    output = ArgumentType.ARGUMENT
    
    if os.path.isfile(argument):
        output = ArgumentType.PATH
    
    elif "," in argument:
        # Check if the provided argument is a comma separated list.
        split_arg = argument.split(",")
        if len(split_arg) > 1:
            output = ArgumentType.LIST

    return output


def get_regex(string: str, ioc_type: IocType, arg_type: ArgumentType) -> list[str] | AllIndicators:
    output = []
    
    RGX_IP = r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    RGX_HASH = r"([a-fA-f0-9]{64}|[a-fA-f0-9]{40}|[a-fA-f0-9]{32})"

    RGX_URL = re.compile(
        r'\bhttps?://(?:www\.)?'
        r'[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{2,6}\b'
        r'(?:[-a-zA-Z0-9()@:%_\+.~#?&/=]*)',
        re.IGNORECASE
    )

    RGX_DOMAIN = re.compile(
        r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b',
        re.IGNORECASE
    )
    
    match ioc_type:
        case IocType.IP:
            output = get_regex_values(RGX_IP, string, arg_type)
        
        case IocType.URL:
            output = get_regex_values(RGX_URL, string, arg_type)
        
        case IocType.DOMAIN:
            output = get_regex_values(RGX_DOMAIN, string, arg_type)
        
        case IocType.HASH:
            output = get_regex_values(RGX_HASH, string, arg_type)
        
        case IocType.ANY:
            output = AllIndicators(
                [],
                [],
                [],
                []
            )

            ips = get_regex_values(RGX_IP, string, arg_type)
            urls =  get_regex_values(RGX_URL, string, arg_type)
            domains = get_regex_values(RGX_DOMAIN, string, arg_type)
            hashes = get_regex_values(RGX_HASH, string, arg_type)

            if ips:
                output.ip = ips

            if urls:
                output.url = urls

            if domains:
                output.domain = domains

            if hashes:
                output.hash = hashes

    return output


def get_regex_values(pattern: str, string: str, arg_type: ArgumentType) -> list[str] | None:
    output = []

    if arg_type == ArgumentType.ARGUMENT:
        output = re.findall(pattern, string)

    elif arg_type == ArgumentType.PATH:
        contents = ""

        with open(string, "r") as f:
            contents = f.read()    
    
        output = re.findall(pattern, contents)

    elif arg_type == ArgumentType.LIST:
        split_string = string.split(",")
        
        for i in split_string:
            chk_value = get_regex_value(pattern, i)

            if chk_value:
                output.append(chk_value)
    
    return output


def get_regex_value(pattern: str, string: str) -> str | None:
    out = re.search(pattern, string)

    if out:
        out = out.group()
        return out