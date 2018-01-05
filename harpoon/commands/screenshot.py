#! /usr/bin/env python
import sys
from harpoon.commands.base import Command
from selenium import webdriver

class CommandScreenshot(Command):
    """
    # Screenshot

    **Takes a screenshot of a webpage**

    `harpoon screenshot http://google.com`
    """
    name = "screenshot"
    description = "Takes a screenshot of a webpage"

    def add_arguments(self, parser):
        parser.add_argument('URL', help='URL of the webpage')
        parser.add_argument('--output', '-o', default="screenshot.png", help='Name of the screenshot image saved')
        self.parser = parser

    def run(self, conf, args, plugins):
        try:
            driver = webdriver.PhantomJS()
            driver.set_window_size(1024, 768) # set the window size that you need
            driver.get(args.URL)
            driver.save_screenshot(args.output)
            print('Webpage %s saved in %s' % (args.URL, args.output))
        except WebDriverException:
            print('Install phantomjs to use this module (npm install -g phantomjs)')
            sys.exit(1)
