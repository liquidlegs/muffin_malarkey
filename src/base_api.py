from src.shared import get_config, Config

class BaseApi:

    def __init__(self):
        self.config: Config = get_config()
        self.debug = self.config.debug
        self.disable_errors = False
        self.web_response = False
        self.rgx = self.config.regex


    def is_api_key_loaded(self) -> bool:
        if self.api_key != None and len(self.api_key) > 0:
            return True
        else:
            return False


    def eprint(self, message: str) -> None:
        if self.disable_errors == True:
            return
        else:
            print(f"Error: {message}")


    def dprint(self, message: str) -> None:
        if self.debug == True:
            print(f"Debug -> {message}")
        else:
            return
        
    