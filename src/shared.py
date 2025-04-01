from enum import Enum
import os
import re
from dataclasses import dataclass, field, asdict
from yaml import safe_load, safe_dump
from json import loads


CONFIG_ENV = "MUFFIN_DEV_CONFIG"
DEFAULT_CONFIG_PATH = "config.yml"

@dataclass
class ConfigFeatures:
    virus_total: bool = False
    alien_vault: bool = False
    threat_fox: bool = False


@dataclass
class ConfigKeys:
    virus_total: str = ""
    alien_vault: str = ""
    threat_fox: str = ""


@dataclass
class Config:
    api_features: ConfigFeatures = field(default_factory = ConfigFeatures)
    keys: ConfigKeys = field(default_factory = ConfigKeys)
    regex: bool = False
    debug: bool = False


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


class FileType(Enum):
    JSON = 0
    YAML = 1
    XML = 2


class ArgumentType(Enum):
    PATH = 0
    LIST = 1
    ARGUMENT = 2


def write_file(filename: str, data: str) -> int:
    with open(filename, "w") as f:
        w_bytes = f.write(data)
        return w_bytes


def save_config(config: Config) -> bool:
    output = None

    try:
        output = safe_dump(config)
        print(output)
    except Exception as e:
        return False
    
    config_path = os.environ.get(CONFIG_ENV)
    if config_path:
        w_bytes = write_file(config_path, output)

        if w_bytes > 0:
            print(f"Successfully wrote {w_bytes} bytes to {config_path}")
            return True
            
    config_path = DEFAULT_CONFIG_PATH
    if config_path:
        w_bytes = write_file(config_path, output)

        if w_bytes > 0:
            print(f"Successfully wrote {w_bytes} bytes to {config_path}")
            return True
        
    return False


def deserialize_file(buffer: str, file_type: FileType) -> str | None:
    output = None
    
    match file_type:
        case FileType.JSON:
            try:
                output = loads(buffer)
                return output
            except Exception as e:
                print(f"Error: {e}")
                return None

        case FileType.YAML:
            try:
                output = safe_load(buffer)
                return output
            except Exception as e:
                print(f"Error: {e}")
                return None


def catch_key_exception(data, key):

    try:
        output = data[key]
        return output
    except Exception as e:
        return None


def read_file(filename: str) -> str | None:
    if os.path.exists(filename) == True:
        buffer = ""

        with open(filename, "r") as f:
            buffer = f.read()
            return buffer
        
    return None


def resolve_config_env():
    config_path = os.environ.get(CONFIG_ENV)
    config_file = None

    if config_path == None:
        print("")
        return None
    
    buffer = read_file(config_path)
    config_file = deserialize_file(buffer, FileType.YAML)

    if config_file == None:
        print("Error: failed to read config file")
        return None
    
    return config_file


def load_config_file(filename: str):
    if filename == None:
        print(f"Error: Failed to resolve config path via environment variables")
        return None
    
    buffer = read_file(filename)
    config_file = deserialize_file(buffer, FileType.YAML)

    if config_file == None:
        print("Error: failed to read config file")
        return None
        
    return config_file


def init_config(config_file: dict) -> Config:
    config = Config()
    api_file = catch_key_exception(config_file, "api_feature")
    keys = catch_key_exception(config_file, "keys")
    vt = catch_key_exception(api_file, "virus_total")
    otx = catch_key_exception(api_file, "alien_vault")
    tfx = catch_key_exception(api_file, "threat_fox")
    dbg = catch_key_exception(config_file, "debug")
    rgx = catch_key_exception(config_file, "regex")

    api_vt = catch_key_exception(keys, "virus_total")
    api_otx = catch_key_exception(keys, "alien_vault")
    api_tfx = catch_key_exception(keys, "threat_fox")

    if vt:
        config.api_features.virus_total = vt

    if otx:
        config.api_features.alien_vault = otx

    if tfx:
        config.api_features.threat_fox = tfx

    if dbg:
        config.debug = dbg

    if rgx:
        config.regex = rgx

    if api_vt:
        config.keys.virus_total = os.environ.get("VT_KEY")

    if api_otx:
        config.keys.virus_total = os.environ.get("OTX_KEY")

    if api_tfx:
        config.keys.virus_total = os.environ.get("TFX_KEY")

    return config


def get_config() -> Config | None:
    config_file = resolve_config_env()
    config = None

    if config_file != None:
        config = init_config(config_file)

    if config == None:
        config_file = load_config_file(DEFAULT_CONFIG_PATH)
        
        if config_file != None:
            config = init_config(config_file)

        else:
            print("Error: failed to load config file from the root of the project directory")
    
    return config


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