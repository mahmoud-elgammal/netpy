import sys
from termcolor import colored

class Argument:
    def __init__(self, args, name,optional, positional=False, position=0,  type=None, required=False, help=None):
        self.args = args
        self.name = name
        self.optional = optional
        self.positional = positional
        self.required = required
        self.position = position
        self.help = help
        self.type = type
        self.ckecked = False

class Cli:
    def __init__(self, command, name="", description=""):
        self.commands = command
        self.args = []
        self.description = description
        self.max_name_length = 0
        self.max_option_length = list()
        self.values = dict()
        self.position = 0
        self.add_argument(["-h", "--help"], "help", optional=True,type=bool, help="Show this help message and exit")

    def create_parser(self):
        pass

    def add_argument(self, args,name, optional=False, positional=False, position=0, required=False, default=None, type=None, help=None):
        arg = Argument(args,name,optional, positional, position=position, required=required, type=type, help=help)
        self.args.append(arg)
        self.set_max_name_length(name)
        self.set_max_option_length(args)
        self.set_default(default, arg)

    def set_default(self, default, arg):
        if default is not None:
            if (arg.type is not None) and (type(default) is not arg.type):
                sys.stderr.write("Invalid default value for {}: {}\n".format(arg.name, arg.default))
                sys.exit(1)
            self.values[arg.name] = default
        else:
            self.values[arg.name] = None

    def compare_names(self, name):
        for arg in self.args:
            if arg.name == name:
                return arg
        return None

    def set_max_name_length(self, name):
        if len(name) > self.max_name_length:
            self.max_name_length = len(name)

    def set_max_option_length(self, options):
        for index, option in enumerate(options):
            if len(self.max_option_length) <= index:
                self.max_option_length.append(len(option))

            if len(option) > self.max_option_length[index]:
                self.max_option_length[index] = len(option)

    def help(self):
        sys.stdout.write("\n")
        sys.stdout.write(colored("Usage: ", "magenta"))
        sys.stdout.write("netpy ")
        sys.stdout.write(colored("[options]", "green"))

        for arg in self.args:
            msg = " "

            if arg.optional:
                msg += arg.args[0]
                msg += " "

            if arg.positional:
                msg += colored("[{}]".format(arg.name), "blue")

            sys.stdout.write(msg)

        sys.stdout.write("\n")
        sys.stdout.write("\n")


        sys.stdout.write(self.description)

        sys.stdout.write("\n")
        sys.stdout.write("\n")

        sys.stdout.write(colored("Posional:", "magenta"))
        sys.stdout.write("\n")


        for arg in self.args:
            if arg.positional:
                sys.stdout.write("  {} {}".format(colored(self.padding(arg.name), "yellow"), arg.help))
                sys.stdout.write("\n")
        sys.stdout.write("\n")

        sys.stdout.write(colored("Options:", "magenta"))
        sys.stdout.write("\n")

        for arg in self.args:
            if not arg.positional:
                sys.stdout.write("  {} {}  {} {}\n".format(colored(self.padding(arg.name), "yellow"), self.padding_option(0, arg.args[0]), self.padding_option(1, arg.args[1]), arg.help))

        sys.stdout.write("\n")


    def padding(self, name):
        return name + (" " * (self.max_name_length - len(name)))

    def padding_option(self, index, option):
        return option + (" " * (self.max_option_length[index] - len(option)))

    def parse_args(self, command):

        ## Parse options
        while 1:
            arg = command[self.position]
            if arg.startswith("-"):
                self.parse_option(arg)
            else:
                self.parse_positional()

            self.position += 1

            if self.position >= len(command):
                break

    def parse_option(self, command):
        found = False

        for arg in self.args:
            for optional in arg.args:
                if optional == command:
                    if arg.ckecked:
                        sys.stderr.write("dublicate option: {}\n".format(arg.name))
                        sys.exit(1)
                    if arg.type is bool:
                        self.values[arg.name] = True
                    else:
                        self.position += 1
                        self.values[arg.name] = self.commands[self.position]

                    if arg.positional:
                        for current_arg in self.args:
                            if current_arg.positional and current_arg.position < arg.position:
                               current_arg.position += 1
                    arg.ckecked = True
                    found = True
                    break

        if not found:
            sys.stderr.write("Invalid option: {}\n".format(command))
            sys.exit(1)

    def parse_positional(self):
        found = False
        for arg in self.args:
            if arg.positional:
                if arg.position == self.position or arg.position == (self.position - len(self.commands)):
                    if arg.ckecked:
                        sys.stderr.write("dublicate positional: {}\n".format(arg.name))
                        sys.exit(1)
                    self.values[arg.name] = self.commands[self.position]
                    arg.ckecked = True
                    found = True
                    break

        if not found:
            sys.stderr.write("Invalid positional argument: {}\n".format(self.commands[self.position]))
            sys.exit(1)


    def run(self):
        if len(self.commands) == 0:
            self.help()
            sys.exit(0)

        self.parse_args(self.commands)

        if self.values["help"]:
            self.help()
            sys.exit(0)

        for arg in self.args:
            if arg.required and self.values[arg.name] is None:
                sys.stderr.write("Missing required argument: {}\n".format(arg.name))
                sys.exit(1)