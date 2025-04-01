from src.shared import IocType, AllIndicators
from src.shared import is_path_or_argment, get_regex, get_config, save_config
from rich.console import Console
from rich.table import Table, box
from rich.panel import Panel
from rich.align import Align
from dataclasses import asdict

VT_ENV = "VT_KEY"
OTX_ENV = "OTX_KEY"
TFX_ENV = "TFX_KEY"

def colour_code_bool(flag: bool) -> str:
    match flag:
        case True:
            return f"[green]{flag}[/]"
        case False:
            return f"[red]{flag}[/]"
        
    return flag


def toggle_features(feature: str) -> None:
    api = get_config()
    config_api = api.api_features

    match feature:
        case "vt" | "virus_total":
            if config_api.virus_total:
                config_api.virus_total = False
                print("Virus total has been disabled")
            elif config_api.virus_total == False:
                config_api.virus_total = True
                print("Virus total has been enabled")
        
        # case "otx" | "alien_vault":
        #     if config_api.alien_vault == True:
        #         config_api.alien_vault = False
        #         print("Alien Vault has been disabled")
        #     else:
        #         config_api.alien_vault = True
        #         print("Alien Vault has been enabled")

        # case "tfx" | "threat_fox":
        #     if config_api.threat_fox == True:
        #         config_api.threat_fox = False
        #         print("Threat Fox has been disabled")
        #     else:
        #         config_api.threat_fox = True
        #         print("Threat Fox has been enabled")

        case "enable_all":
            config_api.virus_total = True
            config_api.alien_vault = True
            config_api.threat_fox = True
        
        case "disable_all":
            config_api.virus_total = False
            config_api.alien_vault = False
            config_api.threat_fox = False

    api.api_features = config_api
    api.keys.virus_total = VT_ENV
    api.keys.alien_vault = OTX_ENV
    api.keys.threat_fox = TFX_ENV

    print(api)
    new_config = asdict(api)
    success = save_config(new_config)

    if success == False:
        print("Error: failed to save to config file")
        return


def show_features():
    config = get_config()
    console = Console()

    # Key-value table
    table = Table(show_header=True, header_style="bold white", expand=True, box=box.SQUARE)
    table.add_column(f"[yellow]Key[/]", justify="left", ratio=1)
    table.add_column(f"[yellow]Value[/]", justify="left", ratio=2)

    table.add_row("Virus Total", colour_code_bool(config.api_features.virus_total))
    table.add_row("Alien Vault", colour_code_bool(config.api_features.alien_vault))
    table.add_row("Threat Fox", colour_code_bool(config.api_features.threat_fox))

    # Combine the title and data table into one output
    text_align = Align("Features", align="center", style="white on blue")
    console.print(Panel(text_align, expand=True))
    console.print(table)


def show_config():
    config = get_config()
    console = Console()

    table = Table(show_header=True, header_style="bold white", expand=True, box=box.SQUARE)
    table.add_column(f"[yellow]Key[/]", justify="left", ratio=1)
    table.add_column(f"[yellow]Value[/]", justify="left", ratio=2)

    vt_value = config.api_features.virus_total
    if vt_value:
        vt_value = f"[bright_red]{'*' * len(config.keys.virus_total)}"
    else:
        vt_value = "NULL"

    otx_value = config.api_features.alien_vault
    if otx_value:
        otx_value = f"[bright_red]{'*' * len(config.keys.alien_vault)}"
    else:
        otx_value = "NULL"

    tfx_value = config.api_features.threat_fox
    if tfx_value:
        tfx_value = f"[bright_red]{'*' * len(config.keys.threat_fox)}"
    else:
        tfx_value = "NULL"

    table.add_row("Debug", colour_code_bool(config.debug))
    table.add_row("Regex", colour_code_bool(config.regex))
    table.add_row("Virus Total API Key", vt_value)
    table.add_row("Alien Vault API Key", otx_value)
    table.add_row("Threat Fox API Key", tfx_value)

    text_align = Align("Configuration", align="center", style="white on blue")
    panel = Panel(text_align, expand=True)
    console.print(panel)
    console.print(table)


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