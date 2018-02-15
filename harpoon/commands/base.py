class Command(object):
    config = None # Describes the configuration params
    update_needed = False

    @property
    def config_needed(self):
        return (self.config is not None)

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
            for c in self.config:
                if c not in conf:
                    return False
                else:
                    for d in self.config[c]:
                        if d not in conf[c]:
                            return False
                        else:
                            if conf[c][d] == '':
                                return False
            return True

    def add_arguments(self, parser):
        pass
