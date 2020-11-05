# How to write plugins

## Define the library

In the `/lib` subfolder you will find the librairies necessary to make your
plugin work. In case there is already a library existing, it is not necessary
to write a new one and you can skip to the next point.

First, you need to define the class of your plugin which will receive an object
as argument.

Example:

```python

class Foo(object):
    """
    Some documentation about the plugin and references
    """

    def __init__(self, key):
        self.key = key
        self.base_url = "http://foo.bar/api/v1"

    def _query(self, query):
        return requests.get(self.base_url + query)
```

Then, you will need to define the functions that, ideally, match the commands you
will define in the command line interface. Those function might vary depending
on the API that you want to integrate.

Example:

```python
def burger(self, query):
    """
    Documentation
    """
    r = requets.get(self.base_url, query)
    if r.ok:
        print(r.json())
    else:
        print("error")
```

When your functions are defined you can start working on your command line
interface.

Full example code:

```python

class Foo(object):
    """
    Some documentation about the plugin and references
    """

    def __init__(self, key):
        self.key = key
        self.base_url = "http://foo.bar/api/v1"

    def _query(self, query):
        return requests.get(self.base_url + query)

    def burger(self, query):
        """
        Documentation
        """
        r = requets.get(self.base_url, query)
        if r.ok:
            print(r.json())
        else:
            print("error")
```


## Define the commands

In the `/commands` subfolder you will find the commands that are available to
the user when running the program. Create a new file with the name of the
website you want to write a plugin for.

* Create a class `CommandNAME_OF_YOUR_PLUGIN` where you will define the commands
available to the user:

Example:

```python
from harpoon.commands.base import Command // required

class CommandFoo(Command):
    """
    # Foo

    * Foo your IoC: `harpoon foo options IoC`
    """

    name = "foo"
    description = "toto"
    config = {"Foo": ["key"]}

```

If necessary, for example if the service Foo requires an API key, you can ask
the user to set this up. Here you will make Harpoon look for the specified key.
More keys and options are available as long as you define them here.

* Declare command line instructions for the user to call:

Example:

```python
def add_arguments(self, parser):
    subparsers = parser.add_subparsers(help="Subcommand") // required
    parser_a = subparsers.add_parsers("burger", help="Use foo with a burger")
    parser_a.add_argument("IoC", help="put your IoC here")
    parser_a.set_defaults(subcommand="burger")

    (... add more commands here ...)

    self.parser = parser // required

```

* Set the workflow for the command to run:

Example:

```python
def run(self, conf, args, plugins):
    yourPlugin = Foo(conf["Foo"]["key"]) // call your plugin and its configuration
    if "subcommand" in args:
        if args.subcommand == "burger":
                yourPlugin.burger(args.ioc)
        else:
            self.parser.print_help() // fallback
    else:
        self.parser.print_help() // fallback

```

To test your code, you will need to recompile the code with: `pip install .`.

Full example code:

```python

from harpoon.commands.base import Command // required
from harpoon.lib.foo import Foo // import your library

class CommandFoo(Command):
    """
    # Foo

    * Foo your IoC: `harpoon foo options IoC`
    """

    name = "foo"
    description = "toto"
    config = {"Foo": ["key"]}

    def add_arguments(self, parser):
        subparsers = parser.add_subparsers(help="Subcommand") // required
        parser_a = subparsers.add_parsers("burger", help="Use foo with a burger")
        parser_a.add_argument("IoC", help="put your IoC here")
        parser_a.set_defaults(subcommand="burger")

        (... add more commands here ...)

        self.parser = parser // required

    def run(self, conf, args, plugins):
        yourPlugin = Foo(conf["Foo"]["key"]) // call your plugin and its configuration
        if "subcommand" in args:
            if args.subcommand == "burger":
                    yourPlugin.burger(args.ioc)
            else:
                self.parser.print_help() // fallback
        else:
            self.parser.print_help() // fallback
```
