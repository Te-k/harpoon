class Command(object):
    config = None # Describes the configuration params
    update_needed = False

    @property
    def config_needed(self):
        if self.config is None:
            return False
        pname = list(self.config.keys())[0]
        return (len(self.config[pname]) > 0)

    def update(self):
        pass

    def test_config(self, conf):
        """
        Test that the config params defined are in the conf file
        """
        if self.config is None:
            return True
        if len(self.config.keys()) == 0:
            return True
        else:
            pname = list(self.config.keys())[0]
            if pname not in conf:
                if len(self.config[pname]) == 0:
                    return True
                else:
                    return False
            else:
                for d in self.config[pname]:
                    if d not in conf[pname]:
                        return False
                    else:
                        if conf[pname][d] == '':
                            return False
            return True

    def check_intel(self, conf):
        """
        Check if intel is disabled in the configuration
        """
        if self.config is None:
            return True
        if len(self.config.keys()) == 0:
            return True
        else:
            pname = list(self.config.keys())[0]
            if pname not in conf:
                return True
            else:
                if "intel" not in conf[pname]:
                    return True
                else:
                    return (conf[pname]["intel"].lower() != "false")
    def intel(self, type, query, data, conf):
        """
        Add information to the global intel command
        type : can be ip or domain (string)
        query : domain or ip address (string)
        data : contains data depending on the type
            For domains: passive_dns, urls, malware, files, reports
        conf : configuration
        """
        pass

    def add_arguments(self, parser):
        pass
