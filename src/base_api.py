import os

class BaseApi:

    def __init__(self, debug=False, response=False):
        self.debug = debug
        self.web_response = response
        self.api_key = None

    def is_api_key_loaded(self) -> bool:
        if self.api_key != None and len(self.api_key) > 0:
            return True
        else:
            return False