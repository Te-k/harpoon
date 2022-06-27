class Subcommand(object):
    """
    Subcommand object that can be used by a Command
    """
    description = ""
    cmd = ""

    def __init__(self, conf):
        self.data = {}
        self._config_data = conf

    def add_arguments(self, parser):
        pass

    def run(self, args):
        raise NotImplementedError()

    def display(self, args):
        """
        Display data
        """
        pass


class Command(object):
    config = None  # Describes the configuration params
    update_needed = False

    def __init__(self, config):
        self._subcommands = {}
        self._config_data = config

    @property
    def config_needed(self):
        if self.config is None:
            return False
        if len(list(self.config.keys())) == 0:
            return False
        pname = list(self.config.keys())[0]
        return (len(self.config[pname]) > 0)

    def update(self):
        pass

    def add_subcommand(self, sc):
        """
        Adds a subcommand to the command
        """
        self._subcommands[sc.cmd] = sc(self._config_data)

    def test_config(self):
        """
        Test that the config params defined are in the conf file
        """
        if self.config is None:
            return True
        if len(self.config.keys()) == 0:
            return True
        else:
            pname = list(self.config.keys())[0]
            if pname not in self._config_data:
                if len(self.config[pname]) == 0:
                    return True
                else:
                    return False
            else:
                for d in self.config[pname]:
                    if d not in self._config_data[pname]:
                        return False
                    else:
                        if self._config_data[pname][d] == '':
                            return False
            return True

    def check_intel(self):
        """
        Check if intel is disabled in the configuration
        """
        if self.config is None:
            return True
        if len(self.config.keys()) == 0:
            return True
        else:
            pname = list(self.config.keys())[0]
            if pname not in self._config_data:
                return True
            else:
                if "intel" not in self._config_data[pname]:
                    return True
                else:
                    return (self._config_data[pname]["intel"].lower() != "false")

    def intel(self, type, query, data):
        """
        Add information to the global intel command
        type : can be ip or domain (string)
        query : domain or ip address (string)
        data : contains data depending on the type
            For domains: passive_dns, urls, malware, files, reports
        """
        if type == "ip":
            self.intel_ip(query, data)
        elif type == "domain":
            self.intel_domain(query, data)
        elif type == "hash":
            self.intel_hash(query, data)
        elif type == "email":
            self.intel_email(query, data)

    def intel_ip(self, query, data):
        """
        Adds information to the global intel command
        """
        pass

    def intel_domain(self, query, data):
        """
        Adds information to the global intel command
        """
        pass

    def intel_hash(self, query, data):
        """
        Adds information to the global intel command
        """
        pass

    def intel_email(self, query, data):
        """
        Adds information to the global intel command
        """
        pass

    def add_arguments(self, parser):
        if len(self._subcommands) > 0:
            subparser = parser.add_subparsers(help='Subcommand')
            for sc in self._subcommands.values():
                p = subparser.add_parser(sc.cmd, help=sc.description)
                sc.add_arguments(p)
                p.set_defaults(subcommand=sc.cmd)
        self._parser = parser

    def run(self, args, plugins):
        """
        Run the command
        """
        if len(self._subcommands) > 0:
            if 'subcommand' in args:
                if args.subcommand in self._subcommands.keys():
                    self._subcommands[args.subcommand].run(args)
                    self._subcommands[args.subcommand].display(args)
                else:
                    self._parser.print_help()
            else:
                self._parser.print_help()
        else:
            raise NotImplementedError()
